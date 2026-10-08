package zkapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/activity"
)

// Video generation is asynchronous at OpenRouter: polling and downloading need
// the key that submitted the job. A video job therefore owns the wallet's
// single lease (requestSlot) from submission until the job fails, is cancelled
// or expires upstream, its outputs have been downloaded, it is deleted
// locally, or the key's usable lifetime ends. Other requests wait for it, as
// they wait for a streaming response.
// Job state is in memory only and contains no prompt; after a restart the
// wallet companion's lease recovery settles the key as usual.
const (
	videoJobPrefix        = "vidjob-"
	maxVideoOutputs       = 8
	maxRetainedVideoJobs  = 64
	videoJobRetention     = time.Hour
	minVideoLeaseLifetime = 30 * time.Second
	maxVideoErrorBytes    = 512
)

type videoJob struct {
	id    string // local identifier; the provider job ID never leaves the client
	model string

	mu        sync.Mutex
	upstream  string
	key       string // cleared on release
	serial    uint64
	expires   time.Time
	status    string
	outputs   int
	fetched   []bool
	inflight  int
	cost      *float64
	byok      *bool
	errorText string
	released  bool
	timer     *time.Timer
	verify    string
	detail    string

	releasedAt time.Time // guarded by Client.videoMu
}

type upstreamVideo struct {
	ID           string   `json:"id"`
	Status       string   `json:"status"`
	UnsignedURLs []string `json:"unsigned_urls"`
	Usage        *struct {
		Cost   *float64 `json:"cost"`
		IsBYOK *bool    `json:"is_byok"`
	} `json:"usage"`
	Error string `json:"error"`
}

func terminalVideoStatus(status string) bool {
	switch status {
	case "completed", "failed", "cancelled", "expired":
		return true
	}
	return false
}

func knownVideoStatus(status string) bool {
	return status == "pending" || status == "in_progress" || terminalVideoStatus(status)
}

func validUpstreamJobID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

// ValidVideoJobID reports whether id has the local job ID format.
func ValidVideoJobID(id string) bool {
	hexPart, ok := strings.CutPrefix(id, videoJobPrefix)
	if !ok || len(hexPart) != 32 {
		return false
	}
	_, err := hex.DecodeString(hexPart)
	return err == nil && strings.ToLower(hexPart) == hexPart
}

func newVideoJobID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return videoJobPrefix + hex.EncodeToString(b[:]), nil
}

func parseUpstreamVideo(body io.Reader) (upstreamVideo, error) {
	data, err := io.ReadAll(io.LimitReader(body, (1<<20)+1))
	var video upstreamVideo
	if err != nil || len(data) > 1<<20 || json.Unmarshal(data, &video) != nil || !knownVideoStatus(video.Status) ||
		len(video.UnsignedURLs) > maxVideoOutputs {
		return upstreamVideo{}, &Error{http.StatusBadGateway, "invalid_upstream_response"}
	}
	if video.Usage != nil && video.Usage.Cost != nil && (math.IsNaN(*video.Usage.Cost) || math.IsInf(*video.Usage.Cost, 0) || *video.Usage.Cost < 0) {
		return upstreamVideo{}, &Error{http.StatusBadGateway, "invalid_upstream_response"}
	}
	return video, nil
}

func setVerificationHeaders(header http.Header, status, detail string) {
	header.Del("X-OA-Verification-Status")
	header.Del("X-OA-Verification-Detail")
	header.Set("X-OA-Verification-Status", status)
	if status == "verifier-unavailable" {
		header.Set("X-OA-Verification-Detail", detail)
	}
}

func localJSONResponse(status int, value any, verify, detail string) (*http.Response, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	header := http.Header{"Content-Type": {"application/json"}}
	if verify != "" {
		setVerificationHeaders(header, verify, detail)
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(bytes.NewReader(data)), ContentLength: int64(len(data))}, nil
}

// view is the local, OpenRouter-shaped job description. URLs point at the
// local API; the provider job ID and key are never included. Caller holds j.mu.
func (j *videoJob) view() map[string]any {
	local := "/v1/videos/" + j.id
	view := map[string]any{"id": j.id, "object": "video.generation", "model": j.model, "status": j.status, "polling_url": local}
	if j.status == "completed" {
		urls := make([]string, j.outputs)
		for i := range urls {
			urls[i] = local + "/content?index=" + strconv.Itoa(i)
		}
		view["unsigned_urls"] = urls
	}
	if j.cost != nil || j.byok != nil {
		usage := map[string]any{}
		if j.cost != nil {
			usage["cost"] = *j.cost
		}
		if j.byok != nil {
			usage["is_byok"] = *j.byok
		}
		view["usage"] = usage
	}
	if j.errorText != "" {
		view["error"] = j.errorText
	}
	if !j.released {
		view["oa_lease_expires_at"] = j.expires.Unix()
	}
	return view
}

// apply records a provider status. Caller holds j.mu.
func (j *videoJob) apply(video upstreamVideo) {
	j.status = video.Status
	if video.Status == "completed" {
		j.outputs = max(len(video.UnsignedURLs), 1)
		j.fetched = make([]bool, j.outputs)
	}
	if video.Usage != nil {
		j.cost, j.byok = video.Usage.Cost, video.Usage.IsBYOK
	}
	if video.Error != "" {
		text := video.Error
		if len(text) > maxVideoErrorBytes {
			text = text[:maxVideoErrorBytes]
		}
		j.errorText = strings.ToValidUTF8(text, "")
	}
}

// finished reports whether the job no longer needs its key. Caller holds j.mu.
func (j *videoJob) finished() bool {
	if !terminalVideoStatus(j.status) {
		return false
	}
	if j.status != "completed" {
		return true
	}
	if j.inflight > 0 {
		return false
	}
	for _, done := range j.fetched {
		if !done {
			return false
		}
	}
	return true
}

// retireSoon ends a key's reuse group now so background settlement retires it
// as soon as the request slot is free. Caller owns requestSlot.
func (c *Client) retireSoon(serial uint64) {
	if group := c.leaseGroup; group != nil && group.serial == serial && c.now().Before(group.until) {
		group.until = c.now()
	}
	select {
	case c.settlementWake <- struct{}{}:
	default:
	}
}

// release returns the job's request slot exactly once. Caller holds j.mu; the
// job owns requestSlot until this returns, so lease fields are safe to update.
func (c *Client) release(ctx context.Context, j *videoJob, complete bool) {
	if j.released {
		return
	}
	j.released = true
	j.key = ""
	if j.timer != nil {
		j.timer.Stop()
	}
	c.cachedLease = nil
	c.retireSoon(j.serial)
	c.videoMu.Lock()
	j.releasedAt = c.now()
	if c.activeVideo == j {
		c.activeVideo = nil
	}
	c.videoMu.Unlock()
	activity.Report(ctx, activity.Event{Kind: activity.KeyReleased, Key: j.serial, Complete: complete})
	<-c.requestSlot
}

// Caller holds videoMu.
func (c *Client) pruneVideoJobsLocked() {
	now := c.now()
	var oldest *videoJob
	released := 0
	for id, job := range c.videoJobs {
		if job.releasedAt.IsZero() {
			continue
		}
		if now.Sub(job.releasedAt) > videoJobRetention {
			delete(c.videoJobs, id)
			continue
		}
		released++
		if oldest == nil || job.releasedAt.Before(oldest.releasedAt) {
			oldest = job
		}
	}
	if len(c.videoJobs) > maxRetainedVideoJobs && oldest != nil {
		delete(c.videoJobs, oldest.id)
	}
}

func (c *Client) videoJob(id string) (*videoJob, error) {
	if !ValidVideoJobID(id) {
		return nil, &Error{http.StatusNotFound, "video_job_not_found"}
	}
	c.videoMu.Lock()
	defer c.videoMu.Unlock()
	c.pruneVideoJobsLocked()
	job := c.videoJobs[id]
	if job == nil {
		return nil, &Error{http.StatusNotFound, "video_job_not_found"}
	}
	return job, nil
}

// SubmitVideo starts one provider video job under a fresh lease and returns
// its local description (202). The submission is never retried.
func (c *Client) SubmitVideo(ctx context.Context, body json.RawMessage) (*http.Response, error) {
	// One submission at a time: a second one waiting for the slot would
	// otherwise start its own job as soon as the first job is released.
	c.videoMu.Lock()
	c.pruneVideoJobsLocked()
	busy := c.activeVideo != nil || c.videoSubmit
	c.videoSubmit = !busy
	c.videoMu.Unlock()
	if busy {
		return nil, &Error{http.StatusConflict, "video_job_active"}
	}
	defer func() {
		c.videoMu.Lock()
		c.videoSubmit = false
		c.videoMu.Unlock()
	}()
	var model struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(body, &model)
	select {
	case c.requestSlot <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	transferred := false
	var selectedKey uint64
	defer func() {
		if !transferred {
			if selectedKey != 0 {
				c.retireSoon(selectedKey)
				activity.Report(ctx, activity.Event{Kind: activity.KeyReleased, Key: selectedKey})
			}
			<-c.requestSlot
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	lease, err := c.waitForLease(ctx, videosEndpoint, body)
	if err != nil {
		return nil, err
	}
	selectedKey = lease.serial
	expires := time.Unix(int64(lease.ExpiresAt)-1, 0)
	if expires.Sub(c.now()) < minVideoLeaseLifetime {
		return nil, &Error{http.StatusServiceUnavailable, "lease_too_short"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Once sent, a submission may create a billed job even if this caller
	// disconnects. Finish reading the provider's answer so the job is tracked.
	submitCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(submitCtx, http.MethodPost, c.config.InferenceBaseURL+videosEndpoint.path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create video request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+lease.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", videosEndpoint.accept)
	response, err := c.inference.Do(req)
	if err != nil {
		return nil, &Error{http.StatusBadGateway, "inference_transport_failed"}
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		header := http.Header{}
		if retry := response.Header.Get("Retry-After"); retry != "" {
			header.Set("Retry-After", retry)
		}
		setVerificationHeaders(header, lease.VerificationStatus, lease.VerificationDetail)
		return &http.Response{StatusCode: response.StatusCode, Header: header, Body: http.NoBody}, nil
	}
	video, err := parseUpstreamVideo(response.Body)
	if err != nil || !validUpstreamJobID(video.ID) {
		return nil, &Error{http.StatusBadGateway, "invalid_upstream_response"}
	}
	id, err := newVideoJobID()
	if err != nil {
		return nil, err
	}
	job := &videoJob{id: id, model: model.Model, upstream: video.ID, key: lease.APIKey, serial: lease.serial,
		expires: expires, verify: lease.VerificationStatus, detail: lease.VerificationDetail}
	job.mu.Lock()
	defer job.mu.Unlock()
	job.apply(video)
	c.videoMu.Lock()
	c.videoJobs[id] = job
	c.activeVideo = job
	c.videoMu.Unlock()
	transferred = true
	if job.finished() {
		c.release(ctx, job, job.status == "completed")
	} else {
		job.timer = time.AfterFunc(expires.Sub(c.now()), func() { c.expireVideoJob(job) })
	}
	return localJSONResponse(http.StatusAccepted, job.view(), job.verify, job.detail)
}

// expireVideoJob releases a job whose key can no longer be used.
func (c *Client) expireVideoJob(j *videoJob) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.released {
		return
	}
	if !terminalVideoStatus(j.status) {
		j.status = "expired"
		j.errorText = "The job's lease ended before the job finished."
	}
	c.release(context.Background(), j, false)
}

// VideoStatus polls the provider while the job holds its lease and returns
// the recorded state afterwards.
func (c *Client) VideoStatus(ctx context.Context, id string) (*http.Response, error) {
	j, err := c.videoJob(id)
	if err != nil {
		return nil, err
	}
	j.mu.Lock()
	if j.released || terminalVideoStatus(j.status) {
		defer j.mu.Unlock()
		return localJSONResponse(http.StatusOK, j.view(), j.verify, j.detail)
	}
	key, upstream := j.key, j.upstream
	j.mu.Unlock()
	pollCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(pollCtx, http.MethodGet, c.config.InferenceBaseURL+"/videos/"+url.PathEscape(upstream), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Accept", "application/json")
	response, err := c.inference.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &Error{http.StatusBadGateway, "inference_transport_failed"}
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		header := http.Header{}
		if retry := response.Header.Get("Retry-After"); retry != "" {
			header.Set("Retry-After", retry)
		}
		return &http.Response{StatusCode: response.StatusCode, Header: header, Body: http.NoBody}, nil
	}
	video, err := parseUpstreamVideo(response.Body)
	if err != nil || (video.ID != "" && video.ID != upstream) {
		return nil, &Error{http.StatusBadGateway, "invalid_upstream_response"}
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if !j.released {
		j.apply(video)
		if j.finished() {
			c.release(ctx, j, j.status == "completed")
		}
	}
	return localJSONResponse(http.StatusOK, j.view(), j.verify, j.detail)
}

// VideoContent streams one output of a completed job. The lease is released
// once every output has been downloaded completely.
func (c *Client) VideoContent(ctx context.Context, id string, index int) (*http.Response, error) {
	j, err := c.videoJob(id)
	if err != nil {
		return nil, err
	}
	j.mu.Lock()
	switch {
	case j.status != "completed":
		j.mu.Unlock()
		return nil, &Error{http.StatusConflict, "video_not_ready"}
	case index < 0 || index >= j.outputs:
		j.mu.Unlock()
		return nil, &Error{http.StatusNotFound, "video_content_not_found"}
	case j.released:
		j.mu.Unlock()
		return nil, &Error{http.StatusGone, "video_content_expired"}
	}
	j.inflight++
	key, upstream, verify, detail := j.key, j.upstream, j.verify, j.detail
	j.mu.Unlock()
	finish := func(complete bool) {
		j.mu.Lock()
		defer j.mu.Unlock()
		j.inflight--
		if j.released {
			return
		}
		if complete {
			j.fetched[index] = true
		}
		if j.finished() {
			c.release(ctx, j, true)
		}
	}
	// Never follow provider-supplied URLs: the key is only sent to the
	// configured inference origin's content endpoint.
	target := c.config.InferenceBaseURL + "/videos/" + url.PathEscape(upstream) + "/content?index=" + strconv.Itoa(index)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		finish(false)
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Accept", "video/*, application/octet-stream")
	response, err := c.inference.Do(req)
	if err != nil {
		finish(false)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &Error{http.StatusBadGateway, "inference_transport_failed"}
	}
	setVerificationHeaders(response.Header, verify, detail)
	ok := response.StatusCode >= 200 && response.StatusCode < 300
	response.Body = holdResponseSlotResult(ctx, response.Body, func(complete bool) { finish(complete && ok) })
	return response, nil
}

// DeleteVideo forgets a finished job and releases its lease early, for
// example when its outputs are not needed. A running job cannot be deleted:
// its provider cost must be final before the key is settled.
func (c *Client) DeleteVideo(ctx context.Context, id string) (*http.Response, error) {
	j, err := c.videoJob(id)
	if err != nil {
		return nil, err
	}
	j.mu.Lock()
	if !j.released && (!terminalVideoStatus(j.status) || j.inflight > 0) {
		j.mu.Unlock()
		return nil, &Error{http.StatusConflict, "video_job_in_progress"}
	}
	c.release(ctx, j, true)
	j.mu.Unlock()
	c.videoMu.Lock()
	delete(c.videoJobs, id)
	c.videoMu.Unlock()
	return localJSONResponse(http.StatusOK, map[string]any{"id": id, "object": "video.generation.deleted", "deleted": true}, "", "")
}
