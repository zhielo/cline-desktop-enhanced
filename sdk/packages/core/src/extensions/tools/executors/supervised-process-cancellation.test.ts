import {EventEmitter} from "node:events";
import {PassThrough} from "node:stream";
import {afterEach,expect,it,vi} from "vitest";
const mocks=vi.hoisted(()=>({spawn:vi.fn()}));
vi.mock("node:child_process",()=>({spawn:mocks.spawn}));
import {runSupervised} from "./supervised-process";
afterEach(()=>{vi.useRealTimers();vi.restoreAllMocks();});
it("reports unconfirmed termination within two seconds when an aborted child never closes",async()=>{
  vi.useFakeTimers();
  vi.spyOn(process,"kill").mockImplementation(()=>true);
  const child=Object.assign(new EventEmitter(),{pid:2147483647,stdout:new PassThrough(),stderr:new PassThrough(),kill:vi.fn(),unref:vi.fn()});
  mocks.spawn.mockReturnValue(child);
  const controller=new AbortController();
  const pending=runSupervised("/owned/idat",[],900000,controller.signal);
  controller.abort();await vi.advanceTimersByTimeAsync(2000);
  expect(await pending).toMatchObject({cancelled:true,timedOut:false,exitCode:null,outputDrainTimedOut:true});
  expect(vi.getTimerCount()).toBe(0);
});
