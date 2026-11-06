package lecore

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func longHistory() []map[string]any {
	messages := []map[string]any{
		{"role": "system", "content": "Retain system guidance."},
		{"role": "developer", "content": "Retain developer guidance."},
	}
	for i := 0; i < 14; i++ {
		messages = append(messages,
			map[string]any{"role": "user", "content": "User turn. " + strings.Repeat("background ", 85)},
			map[string]any{"role": "assistant", "content": "Assistant turn. " + strings.Repeat("context ", 95)})
	}
	messages[4]["content"] = "Thermal aperture calibration project: " + strings.Repeat("thermal aperture calibration ", 30)
	messages[5]["content"] = "The agreed thermal aperture calibration uses a reference image. " + strings.Repeat("thermal aperture calibration ", 20)
	messages[8]["content"] = "SENSITIVE-UNRELATED-HISTORY " + strings.Repeat("background ", 85)
	messages[len(messages)-2]["content"] = "What was the thermal aperture calibration discussed earlier?"
	return messages
}

func requestBody(t *testing.T, messages []map[string]any) json.RawMessage {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"model": "test/model", "messages": messages, "stream": true,
		"temperature": 0.4, "stream_options": map[string]any{"include_usage": true},
		"response_format": map[string]any{"type": "json_object"},
		"metadata":        map[string]any{"nested": []any{"preserve", 7}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func decodedObject(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	return object
}

func TestOptimizeRetainsMatchedExchangeRecentTurnsAndMetadata(t *testing.T) {
	history := longHistory()
	body := requestBody(t, history)
	original := append([]byte(nil), body...)
	optimized, applied := Optimize(body)
	if !applied {
		t.Fatal("expected long relevant history to be reduced")
	}
	if !bytes.Equal(body, original) {
		t.Fatal("Optimize mutated the caller's request")
	}
	if bytes.Contains(optimized, []byte("SENSITIVE-UNRELATED-HISTORY")) {
		t.Fatal("unselected old content crossed the output boundary")
	}
	before, after := decodedObject(t, body), decodedObject(t, optimized)
	for key, value := range before {
		if key != "messages" && !reflect.DeepEqual(value, after[key]) {
			t.Fatalf("non-message field %q changed: %#v -> %#v", key, value, after[key])
		}
	}
	got := after["messages"].([]any)
	if len(got) >= len(history) {
		t.Fatalf("message count did not shrink: %d", len(got))
	}
	if !reflect.DeepEqual(got[:4], []any{history[0], history[1], history[4], history[5]}) {
		t.Fatalf("instruction or matched exchange missing: %#v", got[:4])
	}
	for i := 0; i < 8; i++ {
		if !reflect.DeepEqual(got[len(got)-8+i], history[len(history)-8+i]) {
			t.Fatalf("recent message %d changed", i)
		}
	}
	if !reflect.DeepEqual(got[len(got)-2], history[len(history)-2]) {
		t.Fatal("latest user request was not retained")
	}
}

func TestOptimizePassesUnsafeAndIrrelevantRequestsThroughByteForByte(t *testing.T) {
	tests := map[string]func([]map[string]any){
		"multimodal": func(messages []map[string]any) {
			messages[3]["content"] = []any{map[string]any{"type": "image_url", "image_url": map[string]any{"url": "data:image/png;base64,secret"}}}
		},
		"tool call": func(messages []map[string]any) {
			messages[3]["tool_calls"] = []any{map[string]any{"id": "call_1"}}
		},
		"tool response": func(messages []map[string]any) {
			messages[3]["role"] = "tool"
		},
		"unknown message property": func(messages []map[string]any) {
			messages[3]["name"] = "speaker"
		},
		"inlined attachment": func(messages []map[string]any) {
			messages[3]["content"] = "Document follows\n\n--- File: private.txt ---\nprivate contents"
		},
		"broad query": func(messages []map[string]any) {
			messages[len(messages)-2]["content"] = "Summarize everything in our conversation."
		},
		"unrelated query": func(messages []map[string]any) {
			messages[len(messages)-2]["content"] = "What is the purple monkey dishwasher protocol?"
		},
		"no latest user": func(messages []map[string]any) {
			messages[len(messages)-2]["role"] = "assistant"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			messages := longHistory()
			mutate(messages)
			body := requestBody(t, messages)
			got, applied := Optimize(body)
			if applied || !bytes.Equal(got, body) {
				t.Fatal("unsafe or irrelevant history must return the original request")
			}
		})
	}

	for _, key := range []string{"tools", "functions", "tool_choice", "modalities", "audio", "files", "attachments"} {
		t.Run("request "+key, func(t *testing.T) {
			body := requestBody(t, longHistory())
			var object map[string]json.RawMessage
			if err := json.Unmarshal(body, &object); err != nil {
				t.Fatal(err)
			}
			object[key] = json.RawMessage(`[]`)
			body, _ = json.Marshal(object)
			got, applied := Optimize(body)
			if applied || !bytes.Equal(got, body) {
				t.Fatalf("%s request must pass through", key)
			}
		})
	}
}

func TestOptimizePassesShortAndMalformedBodiesThrough(t *testing.T) {
	short := requestBody(t, []map[string]any{{"role": "user", "content": "Hello"}})
	for _, body := range []json.RawMessage{short, []byte(`{"messages": [`), []byte(`null`), nil} {
		got, applied := Optimize(body)
		if applied || !bytes.Equal(got, body) {
			t.Fatalf("body must pass through unchanged: %s", body)
		}
	}
}

func TestOptimizePassesWeakTravelDecoyThrough(t *testing.T) {
	history := longHistory()
	history[4]["content"] = "I put my passport in the blue desk drawer."
	history[5]["content"] = "Your passport is in the blue desk drawer."
	history[8]["content"] = "We talked about travel arrangements."
	history[9]["content"] = "Travel arrangements are complete."
	history[len(history)-2]["content"] = "Where is my travel document?"
	body := requestBody(t, history)
	got, applied := Optimize(body)
	if applied || !bytes.Equal(got, body) {
		t.Fatal("one shared travel term must not discard the passport location")
	}
}

func TestOptimizePassesLongQuestionFollowedByPasteThrough(t *testing.T) {
	history := longHistory()
	history[len(history)-2]["content"] = "Where is my passport? " + strings.Repeat("thermal aperture calibration ", 200)
	body := requestBody(t, history)
	got, applied := Optimize(body)
	if applied || !bytes.Equal(got, body) {
		t.Fatal("a query beyond 4096 bytes must not rank only its pasted tail")
	}
}

func TestOptimizePassesTemporalQuestionThrough(t *testing.T) {
	for _, query := range []string{
		"How did thermal aperture calibration evolve?",
		"How did thermal aperture calibration change over time?",
		"Compare the initial and final thermal aperture calibration.",
	} {
		t.Run(query, func(t *testing.T) {
			history := longHistory()
			// The later correction does not repeat the named topic. Retrieval of the
			// earlier exchange alone would give the wrong history of the decision.
			history[18]["content"] = "Actually, the reference image was replaced with a measured target."
			history[19]["content"] = "Agreed. The measured target is now the source of truth."
			history[len(history)-2]["content"] = query
			body := requestBody(t, history)
			got, applied := Optimize(body)
			if applied || !bytes.Equal(got, body) {
				t.Fatal("temporal questions need the complete history, including unnamed revisions")
			}
		})
	}
}

func TestRetrievalCascade(t *testing.T) {
	docs := []string{
		"smooth a bumpy surface mesh by laplacian averaging",
		"fluid solver with pressure projection",
		"render an image with adaptive path tracing",
		"denoise a noisy render with joint bilateral filtering",
		"okapi bm25 lexical ranking over documents",
	}
	if ranked, stage := dispatchRetrieval("adaptive path tracing", docs, 6, 0.25, 32); stage != "exact" || ranked[0] != 2 {
		t.Fatalf("exact: %s %#v", stage, ranked)
	}
	if _, stage := dispatchRetrieval("adaptive path tracing", append(docs, "adaptive path tracing again"), 6, 0.25, 32); stage == "exact" {
		t.Fatal("ambiguous phrase must not short circuit")
	}
	if ranked, stage := dispatchRetrieval("fluid solver pressure", docs, 6, 0.25, 32); stage != "dense" || ranked[0] != 1 {
		t.Fatalf("overlap margin: %s %#v", stage, ranked)
	}
	if ranked, stage := dispatchRetrieval("render image", docs, 6, 1, 32); stage != "refine" || ranked[0] != 2 {
		t.Fatalf("BM25 refine: %s %#v", stage, ranked)
	}
	if ranked, stage := dispatchRetrieval("purple monkey dishwasher", docs, 6, 0.25, 32); stage != "abstain" || len(ranked) != 0 {
		t.Fatalf("abstain: %s %#v", stage, ranked)
	}
	a, firstStage := dispatchRetrieval("render image", docs, 6, 1, 32)
	b, secondStage := dispatchRetrieval("render image", docs, 6, 1, 32)
	if firstStage != secondStage || !reflect.DeepEqual(a, b) {
		t.Fatal("retrieval was nondeterministic")
	}
}
