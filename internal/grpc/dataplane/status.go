package dataplane

import (
	"context"

	"github.com/lopster568/phantomDNS/internal/dnsengine"
	pb "github.com/lopster568/phantomDNS/internal/gen/proto/phantomdns/v1"
)

type StatusService struct {
	pb.UnimplementedDataPlaneStatusServiceServer
	engine *dnsengine.Engine
}

func NewStatusService(engine *dnsengine.Engine) *StatusService {
	return &StatusService{
		engine: engine,
	}
}

func (s *StatusService) GetStatus(ctx context.Context, _ *pb.StatusRequest) (*pb.StatusResponse, error) {
	st := s.engine.Status()

	return &pb.StatusResponse{
		Running:          st.Running,
		AcceptingQueries: st.AcceptingQueries,
		PolicyEnabled:    st.PolicyEnabled,
		LastError:        st.LastError,
	}, nil
}

func (s *StatusService) SetAcceptQueries(
	ctx context.Context,
	req *pb.SetAcceptQueriesRequest,
) (*pb.SetAcceptQueriesResponse, error) {

	// Apply desired state to the engine.
	s.engine.SetAcceptQueries(req.Enabled)

	return &pb.SetAcceptQueriesResponse{
		Ok: true,
	}, nil
}

// SetUpstreamResolvers applies a new ordered upstream resolver set to the
// running DNS engine (I-003 live apply).
func (s *StatusService) SetUpstreamResolvers(
	ctx context.Context,
	req *pb.SetUpstreamResolversRequest,
) (*pb.SetUpstreamResolversResponse, error) {

	if err := s.engine.SetUpstreamResolvers(req.Resolvers); err != nil {
		return &pb.SetUpstreamResolversResponse{
			Ok:    false,
			Error: err.Error(),
		}, nil
	}

	return &pb.SetUpstreamResolversResponse{
		Ok: true,
	}, nil
}
