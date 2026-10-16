import { testAndroidToolchain } from "../sdk/packages/core/src/extensions/tools/executors/android-toolchain-fixtures";
const result = await testAndroidToolchain();
if (result.status !== "passed")
	throw new Error("Android owned round-trip acceptance failed");
console.log(JSON.stringify(result, null, 2));
