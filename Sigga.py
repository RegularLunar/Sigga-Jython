# A robust, patch-resistant signature generator for Ghidra.
# Combines sliding-window algorithms, XRef detection, and aggressive smart-masking.
# Automatically retries with lower strictness if a unique signature cannot be found.
# @author lexika, Krixx1337, outercloudstudio, RegularLunar
# @category Functions
# @keybinding
# @menupath
# @toolbar

from ghidra.app.script import GhidraScript
from ghidra.program.model.address import Address, AddressSet
from ghidra.program.model.lang import Register
from ghidra.program.model.scalar import Scalar
from ghidra.util.exception import CancelledException

from java.awt import Toolkit
from java.awt.datatransfer import StringSelection
from java.util import ArrayList, HashSet

MAX_INSTRUCTIONS_TO_SCAN = 200
MIN_WINDOW_BYTES = 5
MAX_WINDOW_BYTES = 128
HEAD_CHECK_SPAN = 3
XREF_CONTEXT_INSTRUCTIONS = 8
MAX_START_OFFSET = 64


class MaskProfile:
    STRICT = 0
    MINIMAL = 1


class SigResult:
    def __init__(self, signature, address, offset, quality, tier):
        self.signature = signature
        self.address = address
        self.offset = offset
        self.quality = quality
        self.tier = tier


class TokenData:
    def __init__(self, tokens, starts):
        self.tokens = tokens
        self.instructionStartIndices = starts


class ByteSignature:
    def __init__(self, s):
        parts = s.strip().split()
        self.bytes = []
        self.mask = []
        for p in parts:
            if "?" in p:
                self.bytes.append(0)
                self.mask.append(0)
            else:
                self.bytes.append(int(p, 16) if int(p, 16) < 128 else int(p, 16) - 256)
                self.mask.append(-1)


def run():
    if currentLocation is None:
        print(
            "Sigga: No cursor location found. Please run this script from the Listing window."
        )
        return

    func = getFunctionContaining(currentLocation.getAddress())
    if func is None:
        print("Sigga: Cursor is not inside a function.")
        return

    print("Sigga: Analyzing {} @ {}".format(func.getName(), func.getEntryPoint()))

    try:
        generateSignatureRoutine(func)
    except CancelledException:
        print("Sigga: Generation cancelled by user.")


def generateSignatureRoutine(func):
    instructions = get_instructions(func.getBody(), MAX_INSTRUCTIONS_TO_SCAN)
    monitor.setMessage("Scanning for Direct Signature...")
    data = tokenizeInstructions(instructions, MaskProfile.STRICT)
    directResult = findCheapestSignature(data, func.getEntryPoint())

    if directResult:
        finish(directResult)
        return

    print("... Direct scan failed. Function is likely generic/duplicate.")
    monitor.setMessage("Checking Tier 3 (XRefs)...")
    xrefResult = tryXRefSignature(func)
    if xrefResult:
        finish(xrefResult)
        return

    print("... Tier 3 failed (No unique XRefs found).")
    monitor.setMessage("Checking Tier 4 (Minimal)...")
    looseData = tokenizeInstructions(instructions, MaskProfile.MINIMAL)
    looseResult = findCheapestSignature(looseData, func.getEntryPoint())

    if looseResult:
        looseResult.tier = "Tier 4 (Low Stability / Desperation)"
        finish(looseResult)
        return

    popup(
        "Failed to generate a unique signature. \n\n"
        + "This function appears to be identical to many others in the binary \n"
        + "and has no unique cross-references."
    )


def finish(result):
    print("==================================================")
    print(" SIGGA SUCCESS - " + result.tier)
    print("==================================================")
    print("Signature:  " + result.signature)
    print("Address:    " + str(result.address))
    print("Offset:     +" + hex(result.offset).replace("0x", "").upper())
    print("Quality:    " + str(result.quality) + "/100")
    print("==================================================")

    copyToClipboard(result.signature)
    print(">> Copied to clipboard.")


def findCheapestSignature(data, startAddr):
    tokens = data.tokens
    n = len(tokens)

    for i in range(n):
        monitor.checkCancelled()

        if i not in data.instructionStartIndices:
            continue
        if i >= MAX_START_OFFSET:
            break

        sig_parts = []
        byteCount = 0

        for j in range(i, n):
            tok = tokens[j]
            sig_parts.append(tok)
            byteCount += 1

            if byteCount < MIN_WINDOW_BYTES:
                continue
            if byteCount > MAX_WINDOW_BYTES:
                break

            isInstructionEnd = (j + 1 == n) or ((j + 1) in data.instructionStartIndices)

            if not isInstructionEnd:
                continue

            currentSig = " ".join(sig_parts)
            if isSignatureUnique(currentSig):
                finalSig = trimTrailingWildcards(currentSig)

                solidHead = not isHeadWeak(tokens, i)
                tier = (
                    "Tier 1 (High Stability, Direct)"
                    if solidHead
                    else "Tier 2 (High Stability, Loose Head)"
                )
                quality = 100 if solidHead else 90

                return SigResult(finalSig, startAddr, i, quality, tier)
    return None


def trimTrailingWildcards(sig):
    parts = sig.split()
    trimCount = 0
    for i in range(len(parts) - 1, -1, -1):
        if parts[i] == "?":
            trimCount += 1
        else:
            break

    if trimCount == 0:
        return sig

    if len(parts) - trimCount < MIN_WINDOW_BYTES:
        trimCount = len(parts) - MIN_WINDOW_BYTES
        if trimCount <= 0:
            return sig

    return " ".join(parts[: len(parts) - trimCount])


def isHeadWeak(tokens, startIndex):
    if startIndex >= len(tokens):
        return True
    if "?" in tokens[startIndex]:
        return True

    checkLen = min(HEAD_CHECK_SPAN, len(tokens) - startIndex)
    wildcards = 0
    for k in range(checkLen):
        if "?" in tokens[startIndex + k]:
            wildcards += 1
    return wildcards > (checkLen / 2)


def tokenizeInstructions(instructions, profile):
    allTokens = []
    starts = set()
    currentOffset = 0

    for insn in instructions:
        starts.add(currentOffset)
        insn_bytes = insn.getBytes()
        tokens = ["%02X" % (b & 0xFF) for b in insn_bytes]

        maskRelocations(insn, tokens)
        maskBranches(insn, tokens)

        if profile == MaskProfile.STRICT:
            maskOperandsSmart(insn, tokens)

        allTokens.extend(tokens)
        currentOffset += len(tokens)

    return TokenData(allTokens, starts)


def maskRelocations(insn, tokens):
    start = insn.getMinAddress()
    end = insn.getMaxAddress()
    rt = currentProgram.getRelocationTable()
    rels = rt.getRelocations(AddressSet(start, end))

    while rels.hasNext():
        r = rels.next()
        offset = int(r.getAddress().subtract(start))
        length = 4
        for i in range(length):
            if (offset + i) < len(tokens):
                tokens[offset + i] = "?"


def maskBranches(insn, tokens):
    if insn.getFlowType().isCall() or insn.getFlowType().isJump():
        if "?" in tokens[0]:
            return

        b0 = int(tokens[0], 16)
        if b0 == 0xE8 or b0 == 0xE9:
            for i in range(1, len(tokens)):
                tokens[i] = "?"
        elif len(tokens) == 2 and (b0 == 0xEB or (b0 & 0xF0) == 0x70):
            tokens[1] = "?"
        elif len(tokens) >= 6 and b0 == 0x0F:
            if "?" not in tokens[1] and (int(tokens[1], 16) & 0xF0) == 0x80:
                for i in range(2, len(tokens)):
                    tokens[i] = "?"


def maskOperandsSmart(insn, tokens):
    try:
        bytes = insn.getBytes()
    except:
        return

    numOps = insn.getNumOperands()
    for op in range(numOps):
        shouldMask = False
        refs = insn.getOperandReferences(op)

        for ref in refs:
            toAddr = ref.getToAddress()
            if toAddr is None:
                continue
            if toAddr.isExternalAddress():
                shouldMask = True
                break
            block = getMemoryBlock(toAddr)
            if block and not block.isExecute():
                shouldMask = True
                break

        if not shouldMask:
            opObjects = insn.getOpObjects(op)
            for obj in opObjects:
                if isinstance(obj, Scalar):
                    val = obj.getUnsignedValue()
                    if val > 0x10000:
                        possibleAddr = (
                            currentProgram.getAddressFactory()
                            .getDefaultAddressSpace()
                            .getAddress(val)
                        )
                        block = getMemoryBlock(possibleAddr)
                        if block and not block.isExecute():
                            shouldMask = True

        if shouldMask:
            for ref in refs:
                toAddr = ref.getToAddress()
                if toAddr:
                    target = toAddr.getOffset()
                    instrEnd = insn.getAddress().add(len(bytes)).getOffset()
                    disp = target - instrEnd
                    maskValueInBytes(tokens, bytes, disp, 4)

            opObjects = insn.getOpObjects(op)
            for obj in opObjects:
                if isinstance(obj, Scalar):
                    val = obj.getUnsignedValue()
                    maskValueInBytes(tokens, bytes, val, 4)
                    maskValueInBytes(tokens, bytes, val, 8)


def maskValueInBytes(tokens, bytes, value, size):
    if size > 8 or len(bytes) < size:
        return
    for i in range(len(bytes) - size + 1):
        currentVal = 0
        for k in range(size):
            currentVal |= (long(bytes[i + k] & 0xFF)) << (k * 8)

        match = False
        if size == 4:
            if (int(currentVal & 0xFFFFFFFF)) == (int(value & 0xFFFFFFFF)):
                match = True
        else:
            if currentVal == value:
                match = True

        if match:
            for k in range(size):
                tokens[i + k] = "?"


def tryXRefSignature(targetFunc):
    funcStart = targetFunc.getEntryPoint()
    refs = getReferencesTo(funcStart)

    for ref in refs:
        if not ref.getReferenceType().isCall():
            continue

        callSite = ref.getFromAddress()
        callerFunc = getFunctionContaining(callSite)
        if callerFunc is None:
            continue

        context = []
        insn = getInstructionAt(callSite)
        if insn is None:
            continue
        context.append(insn)

        next_insn = insn.getNext()
        for k in range(XREF_CONTEXT_INSTRUCTIONS):
            if next_insn is None:
                break
            context.append(next_insn)
            next_insn = next_insn.getNext()

        data = tokenizeInstructions(context, MaskProfile.STRICT)
        fullSig = " ".join(data.tokens)

        if isSignatureUnique(fullSig):
            finalSig = trimTrailingWildcards(fullSig)
            return SigResult(finalSig, callSite, 0, 80, "Tier 3 (XRef / Caller)")
    return None


def isSignatureUnique(sigStr):
    try:
        monitor.checkCancelled()
        sig = ByteSignature(sigStr)
        mem = currentProgram.getMemory()

        firstMatch = mem.findBytes(
            currentProgram.getMinAddress(), sig.bytes, sig.mask, True, monitor
        )
        if firstMatch is None:
            return False

        secondMatch = mem.findBytes(
            firstMatch.add(1),
            currentProgram.getMaxAddress(),
            sig.bytes,
            sig.mask,
            True,
            monitor,
        )
        return secondMatch is None
    except CancelledException:
        raise
    except:
        return False


def get_instructions(body, max_count):
    list_insn = []
    it = currentProgram.getListing().getInstructions(body, True)
    count = 0
    while it.hasNext() and count < max_count:
        list_insn.append(it.next())
        count += 1
    return list_insn


def copyToClipboard(text):
    try:
        c = Toolkit.getDefaultToolkit().getSystemClipboard()
        c.setContents(StringSelection(text), None)
    except Exception as e:
        print("Clipboard copy failed: " + str(e))


if __name__ == "__main__":
    run()
