package s3server

import (
	"encoding/xml"
	"time"
)

// Minimal XML models for S3 responses (MVP scope)

type (
	ListAllMyBucketsResult struct {
		XMLName xml.Name `xml:"ListAllMyBucketsResult"`
		Xmlns   string   `xml:"xmlns,attr"`
		Owner   Owner    `xml:"Owner"`
		Buckets Buckets  `xml:"Buckets"`
	}

	Owner struct {
		ID          string `xml:"ID"`
		DisplayName string `xml:"DisplayName"`
	}

	Buckets struct {
		Bucket []Bucket `xml:"Bucket"`
	}

	Bucket struct {
		Name         string    `xml:"Name"`
		CreationDate time.Time `xml:"CreationDate"`
	}

	ErrorResponse struct {
		XMLName   xml.Name `xml:"Error"`
		Code      string   `xml:"Code"`
		Message   string   `xml:"Message"`
		Resource  string   `xml:"Resource,omitempty"`
		RequestID string   `xml:"RequestId,omitempty"`
		HostID    string   `xml:"HostId,omitempty"`
	}

	ListObjectsV2Result struct {
		XMLName               xml.Name  `xml:"ListBucketResult"`
		Xmlns                 string    `xml:"xmlns,attr"`
		Name                  string    `xml:"Name"`
		Prefix                string    `xml:"Prefix"`
		KeyCount              int       `xml:"KeyCount"`
		MaxKeys               int       `xml:"MaxKeys"`
		Delimiter             string    `xml:"Delimiter,omitempty"`
		IsTruncated           bool      `xml:"IsTruncated"`
		Contents              []Content `xml:"Contents,omitempty"`
		CommonPrefixes        []Prefix  `xml:"CommonPrefixes,omitempty"`
		NextContinuationToken string    `xml:"NextContinuationToken,omitempty"`
	}

	Content struct {
		Key          string    `xml:"Key"`
		LastModified time.Time `xml:"LastModified"`
		ETag         string    `xml:"ETag"`
		Size         int64     `xml:"Size"`
		StorageClass string    `xml:"StorageClass"`
	}

	Prefix struct {
		Prefix string `xml:"Prefix"`
	}
)
