package client

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/go-ctap/ctap/diagnostic"
	"github.com/go-ctap/ctap/protocol"
	ctaptransport "github.com/go-ctap/ctap/transport"
)

func (cl *Client) exchange(ctx context.Context, data []byte) (ctaptransport.CBORResponse, error) {
	if cl.diagnosticSink == nil {
		return cl.transport.CBOR(ctx, data)
	}

	started := time.Now()
	response, err := cl.transport.CBOR(ctx, data)
	duration := time.Since(started)
	cl.emitDiagnostic(ctx, started, duration, data, response, err)

	return response, err
}

func (cl *Client) emitDiagnostic(
	ctx context.Context,
	started time.Time,
	duration time.Duration,
	data []byte,
	response ctaptransport.CBORResponse,
	err error,
) {
	var command protocol.Command
	var requestBody []byte
	if len(data) > 0 {
		command = protocol.Command(data[0])
		requestBody = data[1:]
	}

	requestType, responseType := exchangeSchemas(command)
	request, subCommand := renderDiagnostic(cl.decMode, cl.encMode, requestBody, requestType)
	responseDiagnostic, _ := renderDiagnostic(cl.decMode, cl.encMode, response.Data, responseType)
	event := diagnostic.Exchange{
		StartedAt:  started.UTC(),
		Duration:   duration,
		Command:    command,
		SubCommand: subCommand,
		Request:    request,
		Response:   responseDiagnostic,
		Err:        err,
	}
	if status, ok := exchangeStatus(response, err); ok {
		event.Status = &status
	}

	cl.diagnosticSink(ctx, event)
}

func exchangeSchemas(command protocol.Command) (reflect.Type, reflect.Type) {
	switch command {
	case protocol.AuthenticatorMakeCredential:
		return reflect.TypeFor[protocol.AuthenticatorMakeCredentialRequest](),
			reflect.TypeFor[protocol.AuthenticatorMakeCredentialResponse]()
	case protocol.AuthenticatorGetAssertion:
		return reflect.TypeFor[protocol.AuthenticatorGetAssertionRequest](),
			reflect.TypeFor[protocol.AuthenticatorGetAssertionResponse]()
	case protocol.AuthenticatorGetNextAssertion:
		return nil, reflect.TypeFor[protocol.AuthenticatorGetAssertionResponse]()
	case protocol.AuthenticatorGetInfo:
		return nil, reflect.TypeFor[protocol.AuthenticatorGetInfoResponse]()
	case protocol.AuthenticatorClientPIN:
		return reflect.TypeFor[protocol.AuthenticatorClientPINRequest](),
			reflect.TypeFor[protocol.AuthenticatorClientPINResponse]()
	case protocol.AuthenticatorBioEnrollment, protocol.PrototypeAuthenticatorBioEnrollment:
		return reflect.TypeFor[protocol.AuthenticatorBioEnrollmentRequest](),
			reflect.TypeFor[protocol.AuthenticatorBioEnrollmentResponse]()
	case protocol.AuthenticatorCredentialManagement,
		protocol.PrototypeAuthenticatorCredentialManagement:
		return reflect.TypeFor[protocol.AuthenticatorCredentialManagementRequest](),
			reflect.TypeFor[protocol.AuthenticatorCredentialManagementResponse]()
	case protocol.AuthenticatorLargeBlobs:
		return reflect.TypeFor[protocol.AuthenticatorLargeBlobsRequest](),
			reflect.TypeFor[protocol.AuthenticatorLargeBlobsResponse]()
	case protocol.AuthenticatorConfig:
		return reflect.TypeFor[protocol.AuthenticatorConfigRequest](), nil
	default:
		return nil, nil
	}
}

func exchangeStatus(
	response ctaptransport.CBORResponse,
	err error,
) (ctaptransport.StatusCode, bool) {
	if ctapErr, ok := errors.AsType[*ctaptransport.CTAPError](err); ok {
		return ctapErr.StatusCode, true
	}
	if err == nil {
		return response.StatusCode, true
	}

	return 0, false
}
