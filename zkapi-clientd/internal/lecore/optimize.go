// Package lecore reduces long, plain-text chat history locally before inference.
// The retrieval cascade adapts leCore's deterministic dispatch and BM25/RRF
// algorithms. It never sends, stores, logs, or synthesizes conversation text.
package lecore

import (
	"encoding/json"
	"math"
	"regexp"
	"sort"
	"strings"
)

const (
	minHistoryChars  = 16_000
	recentUserTurns  = 4
	maxOlderMessages = 6
	maxOlderChars    = 12_000
	maxRequestBytes  = 16 << 20
	maxMessages      = 2_000
)

var (
	wordPattern = regexp.MustCompile(`[a-z0-9]+`)
	fileMarker  = regexp.MustCompile(`(?m)^--- File: [^\n]+ ---\s*$`)
	broadQuery  = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(everything|entire|whole|all|every|each|full history|recap|summari[sz]e|so far|throughout)\b`),
		regexp.MustCompile(`(?i)\b(decisions|agreements|takeaways|topics|themes|highlights|action items|next steps|to-dos|todos|commitments)\b`),
		regexp.MustCompile(`(?i)\bacross\s+(?:this|the|our)?\s*(?:chat|conversation|thread|discussion|history)\b`),
		regexp.MustCompile(`(?i)\b(?:what|which)\b[\s\S]*\b(?:discuss|decide|agree|cover)(?:d|s|ed)?\b[\s\S]*\b(?:chat|conversation|thread|discussion)\b`),
		regexp.MustCompile(`(?i)\b(previous|earlier)\s+(messages|conversation|chat|discussion|history)\b`),
		// A timeline can depend on later revisions that use none of the
		// original topic's words, so lexical selection cannot reconstruct it.
		regexp.MustCompile(`(?i)\b(evolv(?:e|ed|es|ing)|evolution|chang(?:e|ed|es|ing)|shift(?:s|ed|ing)?|progress(?:es|ed|ing)?|develop(?:s|ed|ing|ment)?|timeline|chronolog(?:y|ical)|over\s+time|through\s+time|then\s+(?:vs\.?|versus|and)\s+now|before\s+(?:vs\.?|versus|and)\s+after)\b`),
		regexp.MustCompile(`(?i)\b(?:compar(?:e|ed|es|ing|ison)|versus|vs\.?|differ(?:ed|s|ent|ence|ences)?)\b[\s\S]*\b(?:first|last|initial|final|earlier|later|before|after|then|now|previously|originally|today|current(?:ly)?)\b`),
		regexp.MustCompile(`(?i)\b(?:first|last|initial|final|earlier|later|before|after|then|now|previously|originally|today|current(?:ly)?)\b[\s\S]*\b(?:compar(?:e|ed|es|ing|ison)|versus|vs\.?|differ(?:ed|s|ent|ence|ences)?)\b`),
	}
	stopWords = func() map[string]bool {
		words := strings.Fields("a an the of to in on at for and or is are be by with from as it this that these those into over under out up down off no not do does did can could would should will your my our their its his her you we they i he she them us me")
		set := make(map[string]bool, len(words))
		for _, word := range words {
			set[word] = true
		}
		return set
	}()
	// Question framing and references to the conversation are not evidence
	// that an old message answers a specific request.
	queryFrameWords = func() map[string]bool {
		words := strings.Fields("what which where when who whom whose why how was were had has have said say ask asked discuss earlier before previously again about please tell told find locate recall remember remind")
		set := make(map[string]bool, len(words))
		for _, word := range words {
			set[word] = true
		}
		return set
	}()
)

type message struct {
	role    string
	content string
	raw     json.RawMessage
	index   int
}

// Optimize returns the original body and false unless a conservative reduction
// is possible. Lexical retrieval can miss needed context. When it applies,
// only messages changes; every other JSON property retains its original value.
func Optimize(body json.RawMessage) (json.RawMessage, bool) {
	if len(body) == 0 || len(body) > maxRequestBytes {
		return body, false
	}
	var request map[string]json.RawMessage
	if json.Unmarshal(body, &request) != nil || request == nil || hasToolOrMultimodalOptions(request) {
		return body, false
	}
	var rawMessages []json.RawMessage
	if json.Unmarshal(request["messages"], &rawMessages) != nil || len(rawMessages) == 0 || len(rawMessages) > maxMessages {
		return body, false
	}
	messages := make([]message, 0, len(rawMessages))
	originalChars := 0
	for index, raw := range rawMessages {
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || len(fields) != 2 {
			return body, false
		}
		if _, ok := fields["role"]; !ok {
			return body, false
		}
		if _, ok := fields["content"]; !ok {
			return body, false
		}
		var role, content string
		if json.Unmarshal(fields["role"], &role) != nil || json.Unmarshal(fields["content"], &content) != nil {
			return body, false
		}
		if role != "system" && role != "developer" && role != "user" && role != "assistant" {
			return body, false
		}
		if fileMarker.MatchString(content) {
			return body, false
		}
		messages = append(messages, message{role: role, content: content, raw: raw, index: index})
		originalChars += len(content)
	}
	// Some clients include the latest user turn followed by an assistant stub
	// or completed turn. Either shape is safe because both remain in the recent
	// window; a more distant last user is ambiguous and passes through.
	latestUserAtEnd := messages[len(messages)-1].role == "user" ||
		(len(messages) >= 2 && messages[len(messages)-2].role == "user" && messages[len(messages)-1].role == "assistant")
	if originalChars < minHistoryChars || !latestUserAtEnd {
		return body, false
	}

	conversation := make([]message, 0, len(messages))
	users := make([]message, 0, len(messages)/2)
	for _, item := range messages {
		if item.role == "user" || item.role == "assistant" {
			conversation = append(conversation, item)
		}
		if item.role == "user" {
			users = append(users, item)
		}
	}
	if len(users) <= recentUserTurns || len(conversation) < 12 {
		return body, false
	}
	latestStart := users[len(users)-recentUserTurns].index
	if eighthLast := conversation[len(conversation)-8].index; eighthLast < latestStart {
		latestStart = eighthLast
	}
	older := make([]message, 0, len(conversation))
	for _, item := range conversation {
		if item.index < latestStart {
			older = append(older, item)
		}
	}
	if len(older) < 2 {
		return body, false
	}
	if len(users[len(users)-1].content) > 4_096 {
		return body, false
	}
	latestQuery := strings.TrimSpace(users[len(users)-1].content)
	if asksForWholeHistory(latestQuery) {
		return body, false
	}
	query := latestQuery
	if len(query) < 12 {
		query = strings.TrimSpace(users[len(users)-2].content + " " + query)
	}
	if len(query) < 12 || len(query) > 4_096 || asksForWholeHistory(query) {
		return body, false
	}
	signalTerms := querySignalTerms(query)
	if len(signalTerms) < 2 {
		return body, false
	}
	docs := make([]string, len(older))
	for i, item := range older {
		docs[i] = item.content
	}
	ranked, stage := dispatchRetrieval(query, docs, 12, 0.25, 32)
	if stage == "abstain" {
		return body, false
	}
	relevance := tokenOverlapScores(query, docs)
	selected := make(map[int]bool)
	selectedChars := 0
	for _, rankedIndex := range ranked {
		if relevance[rankedIndex] <= 0 {
			continue
		}
		// A single shared word can be a decoy ("travel" does not locate a
		// passport). Require a specific match in one source message before
		// pruning any older history; its adjacent exchange travels with it.
		matchedTerms := querySignalMatches(signalTerms, docs[rankedIndex])
		if matchedTerms < 2 || matchedTerms*3 < len(signalTerms)*2 {
			continue
		}
		source := older[rankedIndex]
		pair := []message{source}
		if source.role == "user" && rankedIndex+1 < len(older) {
			companion := older[rankedIndex+1]
			if companion.role == "assistant" && companion.index == source.index+1 {
				pair = append(pair, companion)
			}
		} else if source.role == "assistant" && rankedIndex > 0 {
			companion := older[rankedIndex-1]
			if companion.role == "user" && companion.index == source.index-1 {
				pair = append(pair, companion)
			}
		}
		fresh := make([]message, 0, len(pair))
		addedChars := 0
		for _, item := range pair {
			if !selected[item.index] {
				fresh = append(fresh, item)
				addedChars += len(item.content)
			}
		}
		if len(selected) == 0 && addedChars > maxOlderChars {
			return body, false
		}
		if selectedChars+addedChars > maxOlderChars || len(selected)+len(fresh) > maxOlderMessages {
			continue
		}
		for _, item := range fresh {
			selected[item.index] = true
		}
		selectedChars += addedChars
		if len(selected) >= maxOlderMessages {
			break
		}
	}
	if len(selected) == 0 {
		return body, false
	}
	kept := make([]json.RawMessage, 0, len(messages))
	optimizedChars := 0
	for _, item := range messages {
		if selected[item.index] || item.index >= latestStart || item.role == "system" || item.role == "developer" {
			kept = append(kept, item.raw)
			optimizedChars += len(item.content)
		}
	}
	if optimizedChars > originalChars*85/100 {
		return body, false
	}
	encoded, err := json.Marshal(kept)
	if err != nil {
		return body, false
	}
	request["messages"] = encoded
	optimized, err := json.Marshal(request)
	if err != nil {
		return body, false
	}
	return optimized, true
}

func hasToolOrMultimodalOptions(request map[string]json.RawMessage) bool {
	for _, key := range []string{"tools", "tool_choice", "parallel_tool_calls", "functions", "function_call", "modalities", "audio", "prediction", "files", "attachments"} {
		if _, exists := request[key]; exists {
			return true
		}
	}
	return false
}

func asksForWholeHistory(query string) bool {
	for _, pattern := range broadQuery {
		if pattern.MatchString(query) {
			return true
		}
	}
	return false
}

func tokenize(input string) []string {
	words := wordPattern.FindAllString(strings.ToLower(input), -1)
	result := make([]string, 0, len(words))
	for _, word := range words {
		if len(word) <= 1 || stopWords[word] {
			continue
		}
		for _, suffix := range []string{"ing", "ed", "es", "s"} {
			if strings.HasSuffix(word, suffix) && len(word)-len(suffix) >= 3 {
				word = strings.TrimSuffix(word, suffix)
				break
			}
		}
		result = append(result, word)
	}
	return result
}

func querySignalTerms(query string) map[string]bool {
	terms := make(map[string]bool)
	for _, term := range tokenize(query) {
		if !queryFrameWords[term] {
			terms[term] = true
		}
	}
	return terms
}

func querySignalMatches(terms map[string]bool, doc string) int {
	present := make(map[string]bool)
	for _, term := range tokenize(doc) {
		present[term] = true
	}
	matches := 0
	for term := range terms {
		if present[term] {
			matches++
		}
	}
	return matches
}

func tokenOverlapScores(query string, docs []string) []float64 {
	terms := make(map[string]bool)
	for _, term := range tokenize(query) {
		terms[term] = true
	}
	scores := make([]float64, len(docs))
	if len(terms) == 0 {
		return scores
	}
	for i, doc := range docs {
		present := make(map[string]bool)
		for _, term := range tokenize(doc) {
			present[term] = true
		}
		for term := range terms {
			if present[term] {
				scores[i]++
			}
		}
		scores[i] /= float64(len(terms))
	}
	return scores
}

type rank struct {
	index int
	score float64
}

func dispatchRetrieval(query string, docs []string, k int, tau float64, shortlist int) ([]int, string) {
	if len(docs) == 0 {
		return nil, "abstain"
	}
	phrase := strings.Join(strings.Fields(strings.ToLower(query)), " ")
	if phrase != "" {
		exact := -1
		for i, doc := range docs {
			if strings.Contains(strings.Join(strings.Fields(strings.ToLower(doc)), " "), phrase) {
				if exact >= 0 {
					exact = -1
					break
				}
				exact = i
			}
		}
		if exact >= 0 {
			return []int{exact}, "exact"
		}
	}
	scores := tokenOverlapScores(query, docs)
	order := make([]int, len(docs))
	for i := range docs {
		order[i] = i
	}
	sort.Slice(order, func(i, j int) bool {
		if scores[order[i]] == scores[order[j]] {
			return order[i] < order[j]
		}
		return scores[order[i]] > scores[order[j]]
	})
	first, second := scores[order[0]], 0.0
	if len(order) > 1 {
		second = scores[order[1]]
	}
	margin := 0.0
	if first > 0 {
		margin = (first - second) / math.Max(first, 1e-12)
	}
	if first > 0 && margin >= tau {
		return order[:min(k, len(order))], "dense"
	}
	window := order[:min(shortlist, len(order))]
	shortDocs := make([]string, len(window))
	for i, original := range window {
		shortDocs[i] = docs[original]
	}
	lexical := bm25Rank(query, shortDocs)
	if first <= 0 && (len(lexical) == 0 || lexical[0].score <= 0) {
		return nil, "abstain"
	}
	fused := make([]rank, len(window))
	for local := range window {
		fused[local] = rank{local, 1 / float64(60+local+1)}
	}
	lexicalRank := 0
	for _, result := range lexical {
		if result.score <= 0 {
			continue
		}
		fused[result.index].score += 0.3 / float64(60+lexicalRank+1)
		lexicalRank++
	}
	sort.Slice(fused, func(i, j int) bool {
		if fused[i].score == fused[j].score {
			return fused[i].index < fused[j].index
		}
		return fused[i].score > fused[j].score
	})
	result := make([]int, 0, min(k, len(fused)))
	for _, item := range fused[:min(k, len(fused))] {
		result = append(result, window[item.index])
	}
	return result, "refine"
}

func bm25Rank(query string, docs []string) []rank {
	queryTerms := tokenize(query)
	frequencies := make([]map[string]int, len(docs))
	lengths := make([]int, len(docs))
	documentFrequencies := make(map[string]int)
	totalLength := 0
	for i, doc := range docs {
		terms := tokenize(doc)
		lengths[i] = len(terms)
		totalLength += len(terms)
		counts := make(map[string]int)
		for _, term := range terms {
			counts[term]++
		}
		frequencies[i] = counts
		for term := range counts {
			documentFrequencies[term]++
		}
	}
	averageLength := float64(totalLength) / float64(max(1, len(docs)))
	ranked := make([]rank, len(docs))
	for i := range ranked {
		ranked[i].index = i
	}
	for _, term := range queryTerms {
		count := documentFrequencies[term]
		if count == 0 {
			continue
		}
		idf := math.Log(1 + (float64(len(docs)-count)+0.5)/(float64(count)+0.5))
		for i := range docs {
			frequency := frequencies[i][term]
			if frequency == 0 {
				continue
			}
			denominator := float64(frequency) + 1.5*(0.25+0.75*float64(lengths[i])/(averageLength+1e-12))
			ranked[i].score += idf * float64(frequency) * 2.5 / (denominator + 1e-12)
		}
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].score == ranked[j].score {
			return ranked[i].index < ranked[j].index
		}
		return ranked[i].score > ranked[j].score
	})
	return ranked
}
