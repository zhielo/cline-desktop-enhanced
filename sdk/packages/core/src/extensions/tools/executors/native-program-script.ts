/** Fixed, reviewed Ghidra script. No caller-supplied scripts or native execution. */
export const GHIDRA_NATIVE_PROGRAM_SCRIPT = String.raw`// Cline V5 bounded static recovery; Apache-2.0 Ghidra API.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.framework.Application;
import com.google.gson.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class ClineNativeProgram extends GhidraScript {
    private String bounded(String value, int limit) {
        return value.length() <= limit ? value : value.substring(0, limit);
    }
    private JsonObject variable(Varnode v) {
        JsonObject out = new JsonObject();
        PcodeOp def = v.getDef();
        String origin = def == null ? "input" : def.getSeqnum().toString();
        out.addProperty("id", v.getAddress().toString() + ":" + v.getSize() + ":" + origin);
        out.addProperty("space", v.getAddress().getAddressSpace().getName());
        out.addProperty("offsetHex", Long.toUnsignedString(v.getOffset(), 16));
        out.addProperty("bytes", v.getSize());
        out.addProperty("constant", v.isConstant());
        return out;
    }
    @Override protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("Expected output and reviewed policy paths");
        JsonObject policy = JsonParser.parseString(Files.readString(Path.of(args[1]), StandardCharsets.UTF_8)).getAsJsonObject();
        int functionLimit = policy.get("maxFunctions").getAsInt();
        int opLimit = policy.get("maxPcodeOps").getAsInt();
        String selector = policy.has("functionName") ? policy.get("functionName").getAsString() : "";
        if (functionLimit < 1 || functionLimit > 64 || opLimit < 1 || opLimit > 4096) throw new IllegalArgumentException("Budget out of bounds");
        JsonObject document = new JsonObject();
        document.addProperty("schemaVersion", 1);
        document.addProperty("producer", "ghidra-high-pcode");
        document.addProperty("engineVersion", Application.getApplicationVersion());
        document.addProperty("language", currentProgram.getLanguageID().toString());
        JsonArray functions = new JsonArray(); document.add("functions", functions);
        int opCount = 0, failed = 0, considered = 0;
        boolean truncated = false;
        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true); decompiler.toggleSyntaxTree(true);
        if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException("Decompiler could not open program");
        try {
            FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
            while (iterator.hasNext()) {
                monitor.checkCancelled();
                Function function = iterator.next();
                if (function.isExternal() || function.isThunk()) continue;
                if (!selector.isEmpty() && !function.getName().equals(selector)) continue;
                considered++;
                if (functions.size() >= functionLimit || opCount >= opLimit) { truncated = true; break; }
                JsonObject item = new JsonObject();
                item.addProperty("name", bounded(function.getName(), 512));
                item.addProperty("entry", function.getEntryPoint().toString());
                JsonArray blocks = new JsonArray(), operations = new JsonArray();
                item.add("blocks", blocks); item.add("pcode", operations);
                DecompileResults result = decompiler.decompileFunction(function, 15, monitor);
                if (!result.decompileCompleted() || result.getHighFunction() == null) {
                    item.addProperty("status", "failed"); item.addProperty("error", bounded(result.getErrorMessage(), 512));
                    item.addProperty("pseudocode", ""); item.addProperty("pseudocodeTruncated", false); failed++;
                } else {
                    HighFunction high = result.getHighFunction();
                    String code = result.getDecompiledFunction() == null ? "" : result.getDecompiledFunction().getC();
                    item.addProperty("pseudocode", bounded(code, 8192)); item.addProperty("pseudocodeTruncated", code.length() > 8192);
                    boolean functionTruncated = code.length() > 8192;
                    if (high.getBasicBlocks().size() > 256) {
                        item.addProperty("status", "partial"); item.addProperty("error", "Function exceeds CFG block budget; CFG and p-code omitted");
                        functionTruncated = true;
                    } else {
                        for (PcodeBlockBasic block : high.getBasicBlocks()) {
                            JsonObject node = new JsonObject(); node.addProperty("id", "b" + block.getIndex());
                            node.addProperty("start", String.valueOf(block.getStart())); node.addProperty("stop", String.valueOf(block.getStop()));
                            JsonArray successors = new JsonArray();
                            if (block.getOutSize() > 32) functionTruncated = true;
                            for (int i = 0; i < Math.min(block.getOutSize(), 32); i++) successors.add("b" + block.getOut(i).getIndex());
                            node.add("successors", successors); blocks.add(node);
                        }
                        Iterator<PcodeOpAST> ops = high.getPcodeOps();
                        while (ops.hasNext()) {
                            monitor.checkCancelled(); PcodeOp op = ops.next(); if (op.isDead()) continue;
                            if (opCount >= opLimit) { functionTruncated = true; break; }
                            if (op.getNumInputs() > 64) { functionTruncated = true; continue; }
                            JsonObject record = new JsonObject(); record.addProperty("id", op.getSeqnum().toString());
                            record.addProperty("address", op.getSeqnum().getTarget().toString());
                            record.addProperty("block", op.getParent() == null ? "unassigned" : "b" + op.getParent().getIndex());
                            record.addProperty("opcode", op.getMnemonic());
                            record.add("output", op.getOutput() == null ? JsonNull.INSTANCE : variable(op.getOutput()));
                            JsonArray inputs = new JsonArray(); for (Varnode input : op.getInputs()) inputs.add(variable(input));
                            record.add("inputs", inputs); operations.add(record); opCount++;
                        }
                        item.addProperty("status", functionTruncated ? "partial" : "recovered");
                    }
                    truncated |= functionTruncated;
                }
                functions.add(item);
            }
        } finally { decompiler.dispose(); }
        JsonObject coverage = new JsonObject(); coverage.addProperty("consideredFunctions", considered);
        coverage.addProperty("failedFunctions", failed); coverage.addProperty("pcodeOperations", opCount);
        coverage.addProperty("truncated", truncated); coverage.addProperty("externalAndThunkFunctionsExcluded", true);
        document.add("coverage", coverage);
        byte[] bytes = new Gson().toJson(document).getBytes(StandardCharsets.UTF_8);
        if (bytes.length > 1048576) throw new IllegalStateException("Program evidence byte budget exceeded");
        Files.write(Path.of(args[0]), bytes, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
    }
}
`;
