package client

import (
	"context"
	"fmt"
	"time"

	pb "github.com/lopster568/phantomDNS/internal/gen/proto/phantomdns/v1"
	v1 "github.com/lopster568/phantomDNS/internal/gen/proto/phantomdns/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Client struct {
	conn    *grpc.ClientConn
	status  pb.DataPlaneStatusServiceClient
	metrics pb.DataPlaneMetricsServiceClient
}

// New creates and connects the gRPC client.
func New(address string) (*Client, error) {
	conn, err := grpc.Dial(address, grpc.WithInsecure()) // TLS later
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	return &Client{
		conn:    conn,
		status:  pb.NewDataPlaneStatusServiceClient(conn),
		metrics: pb.NewDataPlaneMetricsServiceClient(conn),
	}, nil
}

func (c *Client) Close() {
	c.conn.Close()
}

// GetStatus fetches dataplane runtime status.
func (c *Client) GetStatus() (*pb.StatusResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return c.status.GetStatus(ctx, &pb.StatusRequest{})
}

func (c *Client) SetAcceptQueries(enabled bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := c.status.SetAcceptQueries(ctx, &pb.SetAcceptQueriesRequest{
		Enabled: enabled,
	})
	return err
}

func (c *Client) GetLiveQueryMetrics(ctx context.Context) (*v1.LiveQueryMetrics, error) {
	return c.metrics.GetLiveQueryMetrics(ctx, &emptypb.Empty{})
}

// SetUpstreamResolvers applies an ordered upstream resolver set to the
// dataplane, mirroring the apply-via-gRPC pattern used by SetAcceptQueries.
func (c *Client) SetUpstreamResolvers(resolvers []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	resp, err := c.status.SetUpstreamResolvers(ctx, &pb.SetUpstreamResolversRequest{
		Resolvers: resolvers,
	})
	if err != nil {
		return err
	}
	if resp != nil && !resp.Ok {
		return fmt.Errorf("dataplane rejected resolver update: %s", resp.Error)
	}
	return nil
}
