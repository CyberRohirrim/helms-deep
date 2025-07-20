package keto

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	authzDomain "github.com/CyberRohirrim/helms-deep/internal/authorization/domain"
)

// Client represents the Keto client
type Client struct {
	readURL  string
	writeURL string
	client   *http.Client
}

// Config holds Keto client configuration
type Config struct {
	ReadURL  string
	WriteURL string
}

// NewClient creates a new Keto client
func NewClient(config Config) *Client {
	return &Client{
		readURL:  config.ReadURL,
		writeURL: config.WriteURL,
		client:   &http.Client{},
	}
}

// CreateRelationTuple creates a new relation tuple in Keto
func (c *Client) CreateRelation(ctx context.Context, permission *authzDomain.Permission) error {
	tuple := relationTupleRequest{
		Namespace: permission.Namespace,
		Object:    permission.Object,
		Relation:  permission.Relation,
		SubjectID: permission.Subject.ID,
	}

	jsonData, err := json.Marshal(tuple)
	if err != nil {
		return fmt.Errorf("failed to marshal tuple: %w", err)
	}

	url := fmt.Sprintf("%s/admin/relation-tuples", c.writeURL)
	req, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create relation tuple: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// DeleteRelation deletes a relation tuple from Keto
func (c *Client) DeleteRelation(ctx context.Context, permission *authzDomain.Permission) error {
	tuple := relationTupleRequest{
		Namespace: permission.Namespace,
		Object:    permission.Object,
		Relation:  permission.Relation,
		SubjectID: permission.Subject.ID,
	}

	jsonData, err := json.Marshal(tuple)
	if err != nil {
		return fmt.Errorf("failed to marshal tuple: %w", err)
	}

	url := fmt.Sprintf("%s/admin/relation-tuples", c.writeURL)
	req, err := http.NewRequestWithContext(ctx, "DELETE", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete relation tuple: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// Check performs a permission check in Keto
func (c *Client) Check(ctx context.Context, req *authzDomain.CheckRequest) (bool, error) {
	checkReq := checkRequest{
		Namespace: req.Namespace,
		Object:    req.Object,
		Relation:  req.Relation,
		SubjectID: req.Subject.ID,
	}

	jsonData, err := json.Marshal(checkReq)
	if err != nil {
		return false, fmt.Errorf("failed to marshal check request: %w", err)
	}

	url := fmt.Sprintf("%s/relation-tuples/check", c.readURL)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return false, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("check request failed: status %d, body: %s", resp.StatusCode, string(body))
	}

	var checkResp checkResponse
	if err := json.NewDecoder(resp.Body).Decode(&checkResp); err != nil {
		return false, fmt.Errorf("failed to decode response: %w", err)
	}

	return checkResp.Allowed, nil
}

// Expand gets all subjects that have a specific permission on an object
func (c *Client) Expand(ctx context.Context, namespace, object, relation string) (*authzDomain.ExpandResult, error) {
	url := fmt.Sprintf("%s/relation-tuples/expand?namespace=%s&object=%s&relation=%s",
		c.readURL, namespace, object, relation)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("expand request failed: status %d, body: %s", resp.StatusCode, string(body))
	}

	var expandResp expandResponse
	if err := json.NewDecoder(resp.Body).Decode(&expandResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Convert Keto response to domain model
	return &authzDomain.ExpandResult{
		Tree: convertExpandTree(expandResp.Tree),
	}, nil
}

// ListObjects gets all objects a subject has specific permission on
func (c *Client) ListObjects(ctx context.Context, namespace, relation, subjectID string, subjectType authzDomain.SubjectType) ([]string, error) {
	url := fmt.Sprintf("%s/relation-tuples?namespace=%s&relation=%s&subject_id=%s",
		c.readURL, namespace, relation, subjectID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("list objects request failed: status %d, body: %s", resp.StatusCode, string(body))
	}

	var listResp listResponse
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	objects := make([]string, len(listResp.RelationTuples))
	for i, tuple := range listResp.RelationTuples {
		objects[i] = tuple.Object
	}

	return objects, nil
}

// Helper functions and types

type relationTupleRequest struct {
	Namespace string `json:"namespace"`
	Object    string `json:"object"`
	Relation  string `json:"relation"`
	SubjectID string `json:"subject_id"`
}

type checkRequest struct {
	Namespace string `json:"namespace"`
	Object    string `json:"object"`
	Relation  string `json:"relation"`
	SubjectID string `json:"subject_id"`
}

type checkResponse struct {
	Allowed bool `json:"allowed"`
}

type expandResponse struct {
	Tree *expandTreeResponse `json:"tree"`
}

type expandTreeResponse struct {
	Type     string                `json:"type"`
	Subject  *subjectResponse      `json:"subject,omitempty"`
	Children []*expandTreeResponse `json:"children,omitempty"`
}

type subjectResponse struct {
	ID string `json:"id"`
}

type listResponse struct {
	RelationTuples []relationTupleResponse `json:"relation_tuples"`
}

type relationTupleResponse struct {
	Namespace string          `json:"namespace"`
	Object    string          `json:"object"`
	Relation  string          `json:"relation"`
	Subject   subjectResponse `json:"subject"`
}

func convertExpandTree(tree *expandTreeResponse) *authzDomain.ExpandTree {
	if tree == nil {
		return nil
	}

	result := &authzDomain.ExpandTree{
		Type: tree.Type,
	}

	if tree.Subject != nil {
		result.Subject = &authzDomain.Subject{
			ID:   tree.Subject.ID,
			Type: authzDomain.SubjectTypeUser, // Default, could be enhanced
		}
	}

	if len(tree.Children) > 0 {
		result.Children = make([]*authzDomain.ExpandTree, len(tree.Children))
		for i, child := range tree.Children {
			result.Children[i] = convertExpandTree(child)
		}
	}

	return result
}
