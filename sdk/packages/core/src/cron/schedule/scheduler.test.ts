import { describe, expect, it } from "vitest";
import { getNextCronTime } from "./scheduler";

describe("hub scheduler cron helpers", () => {
	it("computes the next matching cron timestamp", () => {
		const after = new Date(2026, 3, 21, 10, 3, 12).getTime();
		const next = getNextCronTime("*/15 * * * *", after);
		expect(next).toBe(new Date(2026, 3, 21, 10, 15, 0).getTime());
	});

	it("computes the next matching cron timestamp in an explicit timezone", () => {
		const after = Date.parse("2026-04-21T15:30:00.000Z");
		const next = getNextCronTime("0 9 * * *", after, "America/New_York");
		expect(next).toBe(Date.parse("2026-04-22T13:00:00.000Z"));
	});
});

describe("bounded timezone calendar scheduling", () => {
	it.each([
		[
			"0 0 1 1 *",
			"2026-01-02T00:00:00Z",
			"Asia/Shanghai",
			"2026-12-31T16:00:00Z",
		],
		[
			"30 2 * * *",
			"2026-03-08T05:00:00Z",
			"America/New_York",
			"2026-03-09T06:30:00Z",
		],
		[
			"30 1 * * *",
			"2026-11-01T05:45:00Z",
			"America/New_York",
			"2026-11-01T06:30:00Z",
		],
		[
			"0 1 * * *",
			"2026-11-01T05:45:00Z",
			"America/New_York",
			"2026-11-01T06:00:00Z",
		],
		["0 0 29 2 *", "2025-03-01T00:00:00Z", "UTC", "2028-02-29T00:00:00Z"],
		[
			"0 0 * * *",
			"2011-12-30T09:00:00Z",
			"Pacific/Apia",
			"2011-12-30T10:00:00Z",
		],
		[
			"45 1 * * *",
			"2026-04-04T15:00:00Z",
			"Australia/Lord_Howe",
			"2026-04-04T15:15:00Z",
		],
	])("resolves %s after %s in %s", (pattern, after, zone, expected) => {
		expect(getNextCronTime(pattern, Date.parse(after), zone)).toBe(
			Date.parse(expected),
		);
	});
	it("rejects impossible calendar dates without scanning minutes", () => {
		const format = Intl.DateTimeFormat.prototype.formatToParts;
		let formats = 0;
		Intl.DateTimeFormat.prototype.formatToParts = function (...args) {
			formats++;
			return format.apply(this, args);
		};
		try {
			expect(() =>
				getNextCronTime(
					"0 0 31 2 *",
					Date.parse("2026-01-02T00:00:00Z"),
					"Asia/Shanghai",
				),
			).toThrow(/No cron occurrence/);
			expect(formats).toBeLessThan(10);
		} finally {
			Intl.DateTimeFormat.prototype.formatToParts = format;
		}
	});
	it("retains day-of-month AND day-of-week behavior", () => {
		expect(
			getNextCronTime("0 0 1 * mon", Date.parse("2026-01-02T00:00:00Z"), "UTC"),
		).toBe(Date.parse("2026-06-01T00:00:00Z"));
	});
	it.each([
		Number.NaN,
		Number.POSITIVE_INFINITY,
		9e20,
	])("rejects invalid timestamps", (after) => {
		expect(() => getNextCronTime("* * * * *", after, "UTC")).toThrow(
			/Invalid cron start/,
		);
	});
});
