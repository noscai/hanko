package flowpilot

import "github.com/teamhanko/hanko/backend/v2/flowpilot/jsonmanager"

// mock_context.go is a ClinicOS fork addition (archon#1874 P1a). It exists so flow actions and
// hooks can be unit-tested without a live Postgres, a FlowDB, or a fully-built flow graph.
//
// Why it has to live in package flowpilot: ExecutionContext.Stash()/Payload() and
// actionExecutionContext.Input() return the UNEXPORTED interfaces stash, payload and
// executionInputSchema. A fake context defined in a downstream package (credential_usage,
// device_trust, ...) therefore cannot satisfy ExecutionContext / HookExecutionContext -- it can
// neither name nor return those types. Only code inside package flowpilot can construct a working
// backing for them, which is what these constructors do.
//
// The returned value is a real *defaultActionExecutionContext with an in-memory stash, payload and
// input schema and NO flow graph or database. That means:
//   - Stash(), Payload(), Input(), Get(), and the stash getters are fully functional.
//   - The flow-graph methods (Continue, Error, Revert, and the hook scheduling helpers) would
//     dereference the nil flow / FlowDB and panic if called.
//
// Downstream tests embed the returned interface and OVERRIDE exactly the capture methods the
// wrapper under test invokes -- Continue, Error, PreventRevert, SuspendAction, Get -- all of which
// have signatures built only from exported types (StateName, FlowError, error, interface{}), so an
// override is expressible outside this package. The three unexported-return getters are inherited
// (delegated to this real backing), never overridden. Uncalled methods are inherited too and would
// panic if hit, which the wrappers never do.

// newMockActionExecutionContext builds a bare *defaultActionExecutionContext backed by an in-memory
// stash / payload / input schema. inputData seeds the input schema read by Input().Get(name).
func newMockActionExecutionContext(inputData map[string]interface{}) *defaultActionExecutionContext {
	s, _ := newStash("__mock_state__")

	in := jsonmanager.NewJSONManager()
	for k, v := range inputData {
		_ = in.Set(k, v)
	}

	fc := &defaultFlowContext{
		stash:   s,
		payload: newPayload(),
	}

	return &defaultActionExecutionContext{
		inputSchema:        newSchemaWithInputData(in),
		defaultFlowContext: fc,
	}
}

// NewMockExecutionContext returns a real ExecutionContext for unit-testing a flow action's
// Execute(c flowpilot.ExecutionContext). inputData is exposed through c.Input().Get(name).
// Seed / inspect flow state through the returned context's Stash().
func NewMockExecutionContext(inputData map[string]interface{}) ExecutionContext {
	return newMockActionExecutionContext(inputData)
}

// NewMockHookExecutionContext returns a real HookExecutionContext for unit-testing a flow hook's
// Execute(c flowpilot.HookExecutionContext). Seed / inspect flow state through Stash().
func NewMockHookExecutionContext() HookExecutionContext {
	return newMockActionExecutionContext(nil)
}
