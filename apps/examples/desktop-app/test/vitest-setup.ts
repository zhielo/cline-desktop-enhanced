// jsdom does not provide ResizeObserver. Several desktop components use it
// through @pierre/diffs, so install one deterministic no-op implementation for
// the test environment instead of letting otherwise-passing suites emit
// unhandled ReferenceErrors.
if (!("ResizeObserver" in globalThis)) {
	Object.defineProperty(globalThis, "ResizeObserver", {
		configurable: true,
		writable: true,
		value: class ResizeObserverStub {
			observe() {}
			unobserve() {}
			disconnect() {}
		},
	});
}
