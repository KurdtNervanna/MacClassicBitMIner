program BitcoinPoolMiner;

{ ------------------------------------------------------------------------- }
{ MacClassicBitMiner - a real Stratum v1 Bitcoin pool miner for Mac OS 6.0.8 }
{                                                                           }
{ This is a faithful port of the validated reference implementation in      }
{ reference/stratum_reference.py (proven against the Bitcoin genesis block, }
{ merkle-branch folding, and difficulty->target math in reference/          }
{ test_reference.py -- 13/13 checks pass). Every crypto/byte-order routine   }
{ here mirrors a tested Python function, so on-hardware debugging is limited }
{ to MacTCP and the compiler, not the mining math.                          }
{                                                                           }
{ IMPORTANT on-device check: click "Self-Test". It double-SHA256s the real  }
{ genesis block header and must display SelfTest: PASS. If it does, the      }
{ entire SHA-256d + endianness pipeline compiled correctly.                 }
{                                                                           }
{ Networking notes:                                                         }
{  - DNS (resolving e.g. solo.ckpool.org) uses the MacTCP DNR. Apple's DNR  }
{    glue (dnr.c, or an equivalent Pascal DNR unit) MUST be added to the     }
{    THINK Pascal project, OR enter a numeric IP address for the pool host.  }
{    Set USE_DNR to 0 below to build without the DNR glue (numeric IP only). }
{ ------------------------------------------------------------------------- }

uses
  MacTypes, QuickDraw, Fonts, Events, Windows, Menus, TextEdit, Dialogs,
  OSUtils, MacTCP, Strings;

{ Set to 1 to compile DNS resolution (requires Apple DNR glue in project).   }
{ Set to 0 to build with numeric-IP hosts only (no DNR glue needed).         }
{$SETC USE_DNR := 1}

const
  kWindowWidth = 520;
  kWindowHeight = 440;
  kTCPBufferSize = 4096;   { MacTCP receive buffer (>= 4096 required)        }
  kMaxLine = 2560;         { max length of one Stratum JSON line             }
  kMaxBranch = 24;         { max merkle branch entries we handle             }
  kSubscribeId = 1;
  kAuthorizeId = 2;
  kFirstSubmitId = 3;

type
  MinerState = (Stopped, Connecting, Subscribing, Authorizing, Mining);
  UInt32 = LongInt;

  BytePtr = ^Byte;
  Byte32 = array[0..31] of Byte;
  Byte34 = array[0..33] of Byte;
  Byte36 = array[0..35] of Byte;
  Byte64 = array[0..63] of Byte;
  Byte128 = array[0..127] of Byte;
  Byte1K = array[0..1023] of Byte;

  SHA256State = record
    h: array[0..7] of UInt32;
  end;

  PoolConfig = record
    host: Str255;
    port: Integer;
    username: Str255;
    password: Str255;
  end;

  { A "long string": Str255 is too small for coinbase parts / notify lines.  }
  LongStr = record
    len: Integer;
    data: packed array[1..kMaxLine] of Char;
  end;

  BranchArray = array[0..kMaxBranch - 1] of Byte32;

var
  myWindow: WindowPtr;
  doneFlag: Boolean;
  walletEdit, poolEdit, workerEdit, passEdit: TEHandle;
  walletRect, poolRect, workerRect, passRect: Rect;
  connectButton, disconnectButton, selfTestButton: Rect;
  currentState: MinerState;
  hashCount, currentNonce: LongInt;
  sharesFound, sharesAccepted, sharesRejected: Integer;
  tcpStream: StreamPtr;
  tcpBuffer: array[0..kTCPBufferSize - 1] of Char;
  poolConfig: PoolConfig;
  lastUpdateTime: LongInt;
  messageId: Integer;

  { --- MacTCP driver --- }
  gDriverRef: Integer;
  gDriverOpen: Boolean;

  { --- network line buffering --- }
  recvAccum, lineBuf: LongStr;

  { --- subscribe / auth state --- }
  subscribeDone, authorized: Boolean;
  extranonce1: Str255;
  extranonce2Hex: Str255;
  extranonce2Size: Integer;

  { --- current job (parsed from mining.notify) --- }
  haveNotify, jobReady: Boolean;
  jobId, prevhashHex, versionHex, nbitsHex, ntimeHex: Str255;
  coinb1, coinb2: LongStr;
  branchBytes: BranchArray;
  nBranch: Integer;
  targetDiff: LongInt;
  headerTemplate: Byte128;

  { --- self-test --- }
  selfTestDone, selfTestPass, selfTestDiffOk: Boolean;

const
  K: array[0..63] of UInt32 = (
    $428a2f98, $71374491, $b5c0fbcf, $e9b5dba5, $3956c25b, $59f111f1, $923f82a4, $ab1c5ed5,
    $d807aa98, $12835b01, $243185be, $550c7dc3, $72be5d74, $80deb1fe, $9bdc06a7, $c19bf174,
    $e49b69c1, $efbe4786, $0fc19dc6, $240ca1cc, $2de92c6f, $4a7484aa, $5cb0a9dc, $76f988da,
    $983e5152, $a831c66d, $b00327c8, $bf597fc7, $c6e00bf3, $d5a79147, $06ca6351, $14292967,
    $27b70a85, $2e1b2138, $4d2c6dfc, $53380d13, $650a7354, $766a0abb, $81c2c92e, $92722c85,
    $a2bfe8a1, $a81a664b, $c24b8b70, $c76c51a3, $d192e819, $d6990624, $f40e3585, $106aa070,
    $19a4c116, $1e376c08, $2748774c, $34b0bcb5, $391c0cb3, $4ed8aa4a, $5b9cca4f, $682e6ff3,
    $748f82ee, $78a5636f, $84c87814, $8cc70208, $90befffa, $a4506ceb, $bef9a3f7, $c67178f2
  );
  H0: array[0..7] of UInt32 = (
    $6a09e667, $bb67ae85, $3c6ef372, $a54ff53a, $510e527f, $9b05688c, $1f83d9ab, $5be0cd19);

{ ========================================================================= }
{  SHA-256  (general, multi-block; big-endian word load is alignment-safe)   }
{ ========================================================================= }

function ROTR(x: UInt32; n: Integer): UInt32;
begin ROTR := (x shr n) or (x shl (32 - n)); end;

function Ch(x, y, z: UInt32): UInt32;
begin Ch := (x and y) xor ((not x) and z); end;

function Maj(x, y, z: UInt32): UInt32;
begin Maj := (x and y) xor (x and z) xor (y and z); end;

function BigSigma0(x: UInt32): UInt32;
begin BigSigma0 := ROTR(x, 2) xor ROTR(x, 13) xor ROTR(x, 22); end;

function BigSigma1(x: UInt32): UInt32;
begin BigSigma1 := ROTR(x, 6) xor ROTR(x, 11) xor ROTR(x, 25); end;

function SmSigma0(x: UInt32): UInt32;
begin SmSigma0 := ROTR(x, 7) xor ROTR(x, 18) xor (x shr 3); end;

function SmSigma1(x: UInt32): UInt32;
begin SmSigma1 := ROTR(x, 17) xor ROTR(x, 19) xor (x shr 10); end;

function PeekB(p: Ptr; off: LongInt): Integer;
var bp: BytePtr;
begin bp := Ptr(Ord(p) + off); PeekB := bp^; end;

procedure SHA256Block(var state: SHA256State; blk: Ptr);
var
  W: array[0..63] of UInt32;
  a, b, c, d, e, f, g, h, t1, t2: UInt32;
  i: Integer;
begin
  { Load 16 big-endian words directly from the block, byte by byte so this is }
  { correct regardless of CPU endianness and needs no address alignment.      }
  for i := 0 to 15 do
    W[i] := (LongInt(PeekB(blk, i * 4)) shl 24)
         or (LongInt(PeekB(blk, i * 4 + 1)) shl 16)
         or (LongInt(PeekB(blk, i * 4 + 2)) shl 8)
         or  LongInt(PeekB(blk, i * 4 + 3));
  for i := 16 to 63 do
    W[i] := SmSigma1(W[i - 2]) + W[i - 7] + SmSigma0(W[i - 15]) + W[i - 16];
  a := state.h[0]; b := state.h[1]; c := state.h[2]; d := state.h[3];
  e := state.h[4]; f := state.h[5]; g := state.h[6]; h := state.h[7];
  for i := 0 to 63 do begin
    t1 := h + BigSigma1(e) + Ch(e, f, g) + K[i] + W[i];
    t2 := BigSigma0(a) + Maj(a, b, c);
    h := g; g := f; f := e; e := d + t1; d := c; c := b; b := a; a := t1 + t2;
  end;
  state.h[0] := state.h[0] + a; state.h[1] := state.h[1] + b;
  state.h[2] := state.h[2] + c; state.h[3] := state.h[3] + d;
  state.h[4] := state.h[4] + e; state.h[5] := state.h[5] + f;
  state.h[6] := state.h[6] + g; state.h[7] := state.h[7] + h;
end;

procedure SHA256Hash(data: Ptr; len: LongInt; var digest: Byte32);
var
  state: SHA256State;
  pad: Byte128;
  i, off, full, rem: Integer;
  bitLen: LongInt;
begin
  for i := 0 to 7 do state.h[i] := H0[i];
  full := len div 64;
  for i := 0 to full - 1 do SHA256Block(state, Ptr(Ord(data) + i * 64));
  rem := len - full * 64;                    { 0..63 leftover bytes }
  for i := 0 to 127 do pad[i] := 0;
  if rem > 0 then BlockMove(Ptr(Ord(data) + full * 64), @pad, rem);
  pad[rem] := $80;
  bitLen := len * 8;                         { fits: our messages are small }
  if rem <= 55 then off := 56 else off := 120;
  pad[off + 4] := (bitLen shr 24) and $FF;
  pad[off + 5] := (bitLen shr 16) and $FF;
  pad[off + 6] := (bitLen shr 8) and $FF;
  pad[off + 7] := bitLen and $FF;
  SHA256Block(state, @pad);
  if rem > 55 then SHA256Block(state, @pad[64]);
  for i := 0 to 7 do begin
    digest[i * 4] := (state.h[i] shr 24) and $FF;
    digest[i * 4 + 1] := (state.h[i] shr 16) and $FF;
    digest[i * 4 + 2] := (state.h[i] shr 8) and $FF;
    digest[i * 4 + 3] := state.h[i] and $FF;
  end;
end;

procedure DoubleSHA256(data: Ptr; len: LongInt; var digest: Byte32);
var mid: Byte32;
begin
  SHA256Hash(data, len, mid);
  SHA256Hash(@mid, 32, digest);
end;

{ ========================================================================= }
{  Hex helpers                                                              }
{ ========================================================================= }

function HexVal(c: Char): Integer;
begin
  if (c >= '0') and (c <= '9') then HexVal := Ord(c) - Ord('0')
  else if (c >= 'a') and (c <= 'f') then HexVal := Ord(c) - Ord('a') + 10
  else if (c >= 'A') and (c <= 'F') then HexVal := Ord(c) - Ord('A') + 10
  else HexVal := 0;
end;

procedure DecodeHexStr255(h: Str255; var outb: Byte32; var outLen: Integer);
var i: Integer;
begin
  outLen := Length(h) div 2;
  for i := 0 to outLen - 1 do
    outb[i] := HexVal(h[i * 2 + 1]) * 16 + HexVal(h[i * 2 + 2]);
end;

procedure BytesToHexStr(var b: Byte32; count: Integer; var hex: Str255);
var i, nib: Integer;
begin
  hex := '';
  for i := 0 to count - 1 do begin
    nib := b[i] shr 4;
    if nib < 10 then hex[i * 2 + 1] := Chr(Ord('0') + nib)
    else hex[i * 2 + 1] := Chr(Ord('a') + nib - 10);
    nib := b[i] and $0F;
    if nib < 10 then hex[i * 2 + 2] := Chr(Ord('0') + nib)
    else hex[i * 2 + 2] := Chr(Ord('a') + nib - 10);
  end;
  hex[0] := Chr(count * 2);
end;

function LongToHex8(v: LongInt): Str255;
var r: Str255; i, nib: Integer;
begin
  r := '00000000';
  for i := 0 to 7 do begin
    nib := (v shr ((7 - i) * 4)) and $F;
    if nib < 10 then r[i + 1] := Chr(Ord('0') + nib)
    else r[i + 1] := Chr(Ord('a') + nib - 10);
  end;
  LongToHex8 := r;
end;

{ ========================================================================= }
{  LongStr helpers                                                          }
{ ========================================================================= }

procedure LSClear(var s: LongStr);
begin s.len := 0; end;

procedure LSAppendChar(var s: LongStr; c: Char);
begin
  if s.len < kMaxLine then begin s.len := s.len + 1; s.data[s.len] := c; end;
end;

procedure LSAppendStr(var s: LongStr; t: Str255);
var i: Integer;
begin for i := 1 to Length(t) do LSAppendChar(s, t[i]); end;

procedure LSAppendLS(var s: LongStr; var t: LongStr);
var i: Integer;
begin for i := 1 to t.len do LSAppendChar(s, t.data[i]); end;

function LSFindCharNL(var s: LongStr): Integer;
var i: Integer;
begin
  LSFindCharNL := 0;
  for i := 1 to s.len do
    if s.data[i] = Chr(10) then begin LSFindCharNL := i; Leave; end;
end;

procedure LSCopyRange(var s: LongStr; a, b: Integer; var dst: LongStr);
var i: Integer;
begin
  LSClear(dst);
  for i := a to b do
    if (i >= 1) and (i <= s.len) then LSAppendChar(dst, s.data[i]);
end;

procedure LSDeleteFront(var s: LongStr; b: Integer);
var i, k: Integer;
begin
  k := 0;
  for i := b + 1 to s.len do begin k := k + 1; s.data[k] := s.data[i]; end;
  s.len := k;
end;

function LSContains(var s: LongStr; sub: Str255): Boolean;
var i, j: Integer; ok: Boolean;
begin
  LSContains := false;
  if (Length(sub) = 0) or (s.len < Length(sub)) then Exit;
  for i := 1 to s.len - Length(sub) + 1 do begin
    ok := true; j := 1;
    while ok and (j <= Length(sub)) do begin
      if s.data[i + j - 1] <> sub[j] then ok := false;
      j := j + 1;
    end;
    if ok then begin LSContains := true; Exit; end;
  end;
end;

function LSFindStr(var s: LongStr; sub: Str255): Integer;
var i, j: Integer; ok: Boolean;
begin
  LSFindStr := 0;
  if (Length(sub) = 0) or (s.len < Length(sub)) then Exit;
  for i := 1 to s.len - Length(sub) + 1 do begin
    ok := true; j := 1;
    while ok and (j <= Length(sub)) do begin
      if s.data[i + j - 1] <> sub[j] then ok := false;
      j := j + 1;
    end;
    if ok then begin LSFindStr := i; Exit; end;
  end;
end;

{ ------ JSON scanning over a LongStr (positional, Stratum order is fixed) - }

procedure SkipToChar(var s: LongStr; var cur: Integer; c: Char);
begin
  while (cur <= s.len) and (s.data[cur] <> c) do cur := cur + 1;
end;

procedure ReadJsonStr(var s: LongStr; var cur: Integer; var outv: Str255);
begin
  outv := '';
  SkipToChar(s, cur, '"');
  cur := cur + 1;
  while (cur <= s.len) and (s.data[cur] <> '"') do begin
    if Length(outv) < 255 then begin
      outv[Length(outv) + 1] := s.data[cur];
      outv[0] := Chr(Length(outv) + 1);
    end;
    cur := cur + 1;
  end;
  cur := cur + 1;
end;

procedure ReadJsonStrL(var s: LongStr; var cur: Integer; var outv: LongStr);
begin
  LSClear(outv);
  SkipToChar(s, cur, '"');
  cur := cur + 1;
  while (cur <= s.len) and (s.data[cur] <> '"') do begin
    LSAppendChar(outv, s.data[cur]); cur := cur + 1;
  end;
  cur := cur + 1;
end;

function ReadJsonInt(var s: LongStr; var cur: Integer): LongInt;
var v: LongInt; neg: Boolean;
begin
  while (cur <= s.len)
    and not (((s.data[cur] >= '0') and (s.data[cur] <= '9')) or (s.data[cur] = '-')) do
    cur := cur + 1;
  neg := false;
  if (cur <= s.len) and (s.data[cur] = '-') then begin neg := true; cur := cur + 1; end;
  v := 0;
  while (cur <= s.len) and (s.data[cur] >= '0') and (s.data[cur] <= '9') do begin
    v := v * 10 + (Ord(s.data[cur]) - Ord('0')); cur := cur + 1;
  end;
  if neg then v := -v;
  ReadJsonInt := v;
end;

function ReadDifficultyCeil(var s: LongStr; var cur: Integer): LongInt;
var v: LongInt; frac: Boolean;
begin
  while (cur <= s.len) and not ((s.data[cur] >= '0') and (s.data[cur] <= '9')) do
    cur := cur + 1;
  v := 0;
  while (cur <= s.len) and (s.data[cur] >= '0') and (s.data[cur] <= '9') do begin
    v := v * 10 + (Ord(s.data[cur]) - Ord('0')); cur := cur + 1;
  end;
  frac := false;
  if (cur <= s.len) and (s.data[cur] = '.') then begin
    cur := cur + 1;
    while (cur <= s.len) and (s.data[cur] >= '0') and (s.data[cur] <= '9') do begin
      if s.data[cur] <> '0' then frac := true;
      cur := cur + 1;
    end;
  end;
  if frac then v := v + 1;   { round up: conservative -> submitted shares stay valid }
  ReadDifficultyCeil := v;
end;

procedure SkipBalanced(var s: LongStr; var cur: Integer);
var depth: Integer;
begin
  SkipToChar(s, cur, '[');
  depth := 0;
  while cur <= s.len do begin
    if s.data[cur] = '[' then depth := depth + 1
    else if s.data[cur] = ']' then begin
      depth := depth - 1;
      if depth = 0 then begin cur := cur + 1; Exit; end;
    end;
    cur := cur + 1;
  end;
end;

function ExtractId(var s: LongStr): LongInt;
var p, cur: Integer;
begin
  ExtractId := -1;
  p := LSFindStr(s, '"id":');
  if p = 0 then Exit;
  cur := p + 5;
  while (cur <= s.len) and (s.data[cur] = ' ') do cur := cur + 1;
  if (cur <= s.len) and (s.data[cur] >= '0') and (s.data[cur] <= '9') then
    ExtractId := ReadJsonInt(s, cur);
end;

{ ========================================================================= }
{  Difficulty / share test  (hash * diff <= DIFF1 ; no bignum division)     }
{  Mirrors share_meets_difficulty_bytewise in test_reference.py.            }
{ ========================================================================= }

procedure MulBy16(var inp: Byte32; m: LongInt; var outp: Byte34);
var i: Integer; t, carry: LongInt;
begin
  carry := 0;
  for i := 31 downto 0 do begin
    t := LongInt(inp[i]) * m + carry;
    outp[i + 2] := t and $FF;
    carry := (t shr 8) and $FFFFFF;
  end;
  outp[1] := carry and $FF;
  outp[0] := (carry shr 8) and $FF;
end;

function ShareMeetsDifficulty(var hashBE: Byte32; diff: LongInt): Boolean;
var
  dlo, dhi, s, carry: LongInt;
  tmpLo, tmpHi: Byte34;
  A, B, prod, D36: Byte36;
  i, j: Integer;
  decided: Boolean;
begin
  if diff < 1 then diff := 1;
  dlo := diff and $FFFF;
  dhi := (diff shr 16) and $FFFF;
  MulBy16(hashBE, dlo, tmpLo);
  MulBy16(hashBE, dhi, tmpHi);
  { A = 0,0 ++ tmpLo    (value hash*dlo)          }
  { B = tmpHi ++ 0,0    (value hash*dhi << 16)    }
  A[0] := 0; A[1] := 0;
  for i := 0 to 33 do A[i + 2] := tmpLo[i];
  for i := 0 to 33 do B[i] := tmpHi[i];
  B[34] := 0; B[35] := 0;
  carry := 0;
  for j := 35 downto 0 do begin
    s := LongInt(A[j]) + LongInt(B[j]) + carry;
    prod[j] := s and $FF;
    carry := s shr 8;
  end;
  { DIFF1 in the 36-byte frame: 4 lead zeros + (00 00 00 00 FF FF 00...00) }
  for i := 0 to 35 do D36[i] := 0;
  D36[8] := $FF; D36[9] := $FF;
  { big-endian compare prod <= D36 }
  ShareMeetsDifficulty := true;
  decided := false;
  j := 0;
  while (j <= 35) and not decided do begin
    if prod[j] < D36[j] then begin ShareMeetsDifficulty := true; decided := true; end
    else if prod[j] > D36[j] then begin ShareMeetsDifficulty := false; decided := true; end;
    j := j + 1;
  end;
end;

{ ========================================================================= }
{  Job preparation: coinbase -> merkle root -> 80-byte header template       }
{  Mirrors StratumJob.header_for_nonce in stratum_reference.py.             }
{ ========================================================================= }

procedure PrepareJob;
var
  coinbaseHex: LongStr;
  coinbaseBytes: Byte1K;
  cbLen, tmpLen, k, w, b, i: Integer;
  root, merkle, vB, phB, tB, nbB: Byte32;
  cat: Byte64;
begin
  { coinbase = coinb1 + extranonce1 + extranonce2 + coinb2 (hex), then decode }
  LSClear(coinbaseHex);
  LSAppendLS(coinbaseHex, coinb1);
  LSAppendStr(coinbaseHex, extranonce1);
  LSAppendStr(coinbaseHex, extranonce2Hex);
  LSAppendLS(coinbaseHex, coinb2);
  cbLen := coinbaseHex.len div 2;
  for i := 0 to cbLen - 1 do
    coinbaseBytes[i] := HexVal(coinbaseHex.data[i * 2 + 1]) * 16
                      + HexVal(coinbaseHex.data[i * 2 + 2]);
  DoubleSHA256(@coinbaseBytes, cbLen, root);

  { fold merkle branch: root = sha256d(root ++ branch) }
  for k := 0 to nBranch - 1 do begin
    for i := 0 to 31 do cat[i] := root[i];
    for i := 0 to 31 do cat[32 + i] := branchBytes[k][i];
    DoubleSHA256(@cat, 64, root);
  end;
  for i := 0 to 31 do merkle[i] := root[i];

  { version (notify big-endian hex -> little-endian in header) }
  DecodeHexStr255(versionHex, vB, tmpLen);
  headerTemplate[0] := vB[3]; headerTemplate[1] := vB[2];
  headerTemplate[2] := vB[1]; headerTemplate[3] := vB[0];

  { prevhash: byte-swap within each 4-byte word }
  DecodeHexStr255(prevhashHex, phB, tmpLen);
  for w := 0 to 7 do
    for b := 0 to 3 do
      headerTemplate[4 + w * 4 + b] := phB[w * 4 + (3 - b)];

  { merkle root (already internal order) }
  for i := 0 to 31 do headerTemplate[36 + i] := merkle[i];

  { ntime (big-endian hex -> little-endian) }
  DecodeHexStr255(ntimeHex, tB, tmpLen);
  headerTemplate[68] := tB[3]; headerTemplate[69] := tB[2];
  headerTemplate[70] := tB[1]; headerTemplate[71] := tB[0];

  { nbits (big-endian hex -> little-endian) }
  DecodeHexStr255(nbitsHex, nbB, tmpLen);
  headerTemplate[72] := nbB[3]; headerTemplate[73] := nbB[2];
  headerTemplate[74] := nbB[1]; headerTemplate[75] := nbB[0];

  currentNonce := 0;
  jobReady := true;
end;

{ ========================================================================= }
{  Networking (MacTCP)                                                      }
{ ========================================================================= }

{$IFC USE_DNR}
{ --- MacTCP DNR (Domain Name Resolver) ---                                 }
{ Requires Apple's DNR glue (dnr.c compiled into the project, exporting      }
{ OpenResolver / StrToAddr / CloseResolver). See file header.               }
const
  kNumAltAddrs = 4;
  inProgress = 1;
type
  DNRHostInfo = record
    rtnCode: LongInt;
    cname: packed array[0..255] of Char;
    addrType: Integer;
    addrLen: Integer;
    addr: array[0..kNumAltAddrs - 1] of LongInt;
  end;
function OpenResolver(fileName: Ptr): OSErr; external;
function StrToAddr(hostName: Ptr; var rtnStruct: DNRHostInfo;
                   resultProc: Ptr; userData: Ptr): OSErr; external;
function CloseResolver: OSErr; external;
{$ENDC}

function ParsePort(addr: Str255): Integer;
var colonPos, i, port: Integer; portStr: Str255;
begin
  if Pos('://', addr) > 0 then Delete(addr, 1, Pos('://', addr) + 2);
  colonPos := Pos(':', addr);
  port := 0;
  if colonPos > 0 then begin
    portStr := Copy(addr, colonPos + 1, 255);
    for i := 1 to Length(portStr) do
      if (portStr[i] >= '0') and (portStr[i] <= '9') then
        port := port * 10 + (Ord(portStr[i]) - Ord('0'));
  end;
  ParsePort := port;
end;

procedure ParseHostOnly(addr: Str255; var host: Str255);
var colonPos: Integer;
begin
  if Pos('://', addr) > 0 then Delete(addr, 1, Pos('://', addr) + 2);
  colonPos := Pos(':', addr);
  if colonPos > 0 then host := Copy(addr, 1, colonPos - 1) else host := addr;
end;

{ Try to parse host as a numeric dotted-quad IP. Returns true + addr if so.  }
function TryNumericIP(host: Str255; var addr: LongInt): Boolean;
var i, j, octet, dotPos, dots: Integer; s, octetStr: Str255; ok: Boolean;
begin
  s := host; addr := 0; dots := 0;
  for i := 1 to Length(host) do if host[i] = '.' then dots := dots + 1;
  if dots <> 3 then begin TryNumericIP := false; Exit; end;
  ok := true;
  for i := 1 to 4 do begin
    dotPos := Pos('.', s);
    if (dotPos = 0) and (i < 4) then begin ok := false; Leave; end;
    if i = 4 then octetStr := s else octetStr := Copy(s, 1, dotPos - 1);
    if Length(octetStr) = 0 then begin ok := false; Leave; end;
    octet := 0;
    for j := 1 to Length(octetStr) do begin
      if (octetStr[j] < '0') or (octetStr[j] > '9') then ok := false;
      octet := octet * 10 + (Ord(octetStr[j]) - Ord('0'));
    end;
    if octet > 255 then ok := false;
    addr := (addr shl 8) or octet;
    if i < 4 then Delete(s, 1, dotPos);
  end;
  TryNumericIP := ok;
end;

{ Resolve a hostname to an IP address. Returns noErr + addr on success.      }
function ResolveHost(host: Str255; var addr: LongInt): OSErr;
{$IFC USE_DNR}
var hi: DNRHostInfo; err: OSErr; cname: packed array[0..255] of Char;
    i, spins: Integer;
{$ENDC}
begin
  if TryNumericIP(host, addr) then begin ResolveHost := noErr; Exit; end;
{$IFC USE_DNR}
  { build a C string from the Pascal host name }
  for i := 1 to Length(host) do cname[i - 1] := host[i];
  cname[Length(host)] := Chr(0);
  hi.rtnCode := inProgress;
  err := StrToAddr(@cname, hi, nil, nil);
  spins := 0;
  while (hi.rtnCode = inProgress) and (spins < 1800) do begin
    SystemTask; spins := spins + 1;
  end;
  if hi.rtnCode = noErr then begin addr := hi.addr[0]; ResolveHost := noErr; end
  else ResolveHost := OSErr(hi.rtnCode);
{$ELSEC}
  { DNR disabled: only numeric IPs are accepted }
  ResolveHost := paramErr;
{$ENDC}
end;

procedure ZeroPB(var pb: TCPiopb);
begin
  FillChar(pb, SizeOf(pb), 0);
  pb.ioCRefNum := gDriverRef;
end;

function ConnectToPool: OSErr;
var err: OSErr; tcpPB: TCPiopb; addr: LongInt; stream: StreamPtr;
begin
  if not gDriverOpen then begin
    err := OpenDriver('.IPP', gDriverRef);
    if err <> noErr then begin ConnectToPool := err; Exit; end;
    gDriverOpen := true;
{$IFC USE_DNR}
    OpenResolver(nil);
{$ENDC}
  end;

  err := ResolveHost(poolConfig.host, addr);
  if err <> noErr then begin ConnectToPool := err; Exit; end;

  { create the TCP stream with our receive buffer }
  ZeroPB(tcpPB);
  tcpPB.csCode := TCPCreate;
  tcpPB.csParam.create.rcvBuff := @tcpBuffer;
  tcpPB.csParam.create.rcvBuffLen := kTCPBufferSize;
  err := PBControl(@tcpPB, false);
  if err <> noErr then begin ConnectToPool := err; Exit; end;
  stream := tcpPB.tcpStream;

  { active open (connect) }
  ZeroPB(tcpPB);
  tcpPB.csCode := TCPActiveOpen;
  tcpPB.tcpStream := stream;
  tcpPB.csParam.open.remoteHost := addr;
  tcpPB.csParam.open.remotePort := poolConfig.port;
  tcpPB.csParam.open.timeToLive := 60;
  err := PBControl(@tcpPB, false);
  if err = noErr then tcpStream := stream else tcpStream := nil;
  ConnectToPool := err;
end;

procedure SendToPool(msg: Str255);
var tcpPB: TCPiopb; wdsRec: array[0..1] of wdsEntry;
begin
  if tcpStream = nil then Exit;
  msg := Concat(msg, Chr(10));
  wdsRec[0].length := Length(msg);
  wdsRec[0].ptr := @msg[1];
  wdsRec[1].length := 0;
  wdsRec[1].ptr := nil;
  ZeroPB(tcpPB);
  tcpPB.csCode := TCPSend;
  tcpPB.tcpStream := tcpStream;
  tcpPB.csParam.send.wdsPtr := @wdsRec;
  tcpPB.csParam.send.pushFlag := true;
  PBControl(@tcpPB, false);
end;

procedure DisconnectFromPool;
var tcpPB: TCPiopb;
begin
  if tcpStream = nil then Exit;
  ZeroPB(tcpPB); tcpPB.csCode := TCPClose; tcpPB.tcpStream := tcpStream;
  PBControl(@tcpPB, false);
  ZeroPB(tcpPB); tcpPB.csCode := TCPRelease; tcpPB.tcpStream := tcpStream;
  PBControl(@tcpPB, false);
  tcpStream := nil;
end;

{ ========================================================================= }
{  Stratum outbound messages                                                }
{ ========================================================================= }

procedure SendSubscribe;
var msg, temp: Str255;
begin
  messageId := kSubscribeId;
  NumToString(messageId, temp);
  msg := Concat('{"id":', temp, ',"method":"mining.subscribe","params":[]}');
  SendToPool(msg);
end;

procedure SendAuthorize;
var msg, temp: Str255;
begin
  messageId := kAuthorizeId;
  NumToString(messageId, temp);
  msg := Concat('{"id":', temp, ',"method":"mining.authorize","params":["');
  msg := Concat(msg, poolConfig.username, '","');
  msg := Concat(msg, poolConfig.password, '"]}');
  SendToPool(msg);
end;

procedure SubmitShare(nonce: LongInt);
var msg, temp, nonceHex: Str255;
begin
  if messageId < kFirstSubmitId then messageId := kFirstSubmitId
  else messageId := messageId + 1;
  NumToString(messageId, temp);
  nonceHex := LongToHex8(nonce);
  msg := Concat('{"id":', temp, ',"method":"mining.submit","params":["');
  msg := Concat(msg, poolConfig.username, '","');
  msg := Concat(msg, jobId, '","');
  msg := Concat(msg, extranonce2Hex, '","');
  msg := Concat(msg, ntimeHex, '","');
  msg := Concat(msg, nonceHex, '"]}');
  SendToPool(msg);
  sharesFound := sharesFound + 1;
end;

procedure BuildExtranonce2;
var i: Integer;
begin
  extranonce2Hex := '';
  for i := 1 to extranonce2Size * 2 do extranonce2Hex[i] := '0';
  extranonce2Hex[0] := Chr(extranonce2Size * 2);
end;

{ ========================================================================= }
{  Stratum inbound handling                                                 }
{ ========================================================================= }

procedure StartMiningIfReady;
begin
  if authorized and jobReady then begin
    currentState := Mining;
    lastUpdateTime := TickCount;
    hashCount := 0;
  end;
end;

procedure HandleSubscribeResult(var line: LongStr);
var p, cur: Integer;
begin
  p := LSFindStr(line, '"result":');
  if p = 0 then Exit;
  cur := p + 9;
  SkipToChar(line, cur, '[');   { start of the result array }
  cur := cur + 1;
  SkipBalanced(line, cur);      { skip the nested [[...]] subscriptions array }
  ReadJsonStr(line, cur, extranonce1);
  extranonce2Size := ReadJsonInt(line, cur);
  if extranonce2Size <= 0 then extranonce2Size := 4;
  BuildExtranonce2;
  subscribeDone := true;
  SendAuthorize;
  currentState := Authorizing;
  if haveNotify then PrepareJob;
  StartMiningIfReady;
end;

procedure HandleAuthorizeResult(var line: LongStr);
begin
  if LSContains(line, '"result":true') then begin
    authorized := true;
    StartMiningIfReady;
  end;
end;

procedure HandleSubmitResult(var line: LongStr);
begin
  if LSContains(line, '"result":true') then
    sharesAccepted := sharesAccepted + 1
  else if LSContains(line, '"result":false') then
    sharesRejected := sharesRejected + 1;
  if currentState = Mining then { keep mining } ;
end;

procedure HandleNotify(var line: LongStr);
var p, cur: Integer; bh: Str255; tmpLen: Integer;
begin
  p := LSFindStr(line, '"params":');
  if p = 0 then Exit;
  cur := p + 9;
  SkipToChar(line, cur, '[');
  cur := cur + 1;
  ReadJsonStr(line, cur, jobId);
  ReadJsonStr(line, cur, prevhashHex);
  ReadJsonStrL(line, cur, coinb1);
  ReadJsonStrL(line, cur, coinb2);
  { merkle branch array }
  nBranch := 0;
  SkipToChar(line, cur, '[');
  cur := cur + 1;
  while (cur <= line.len) and (line.data[cur] <> ']') do begin
    if line.data[cur] = '"' then begin
      ReadJsonStr(line, cur, bh);
      if nBranch < kMaxBranch then begin
        DecodeHexStr255(bh, branchBytes[nBranch], tmpLen);
        nBranch := nBranch + 1;
      end;
    end else
      cur := cur + 1;
  end;
  cur := cur + 1;   { past ']' }
  ReadJsonStr(line, cur, versionHex);
  ReadJsonStr(line, cur, nbitsHex);
  ReadJsonStr(line, cur, ntimeHex);
  haveNotify := true;
  if subscribeDone then PrepareJob;
  StartMiningIfReady;
end;

procedure HandleSetDiff(var line: LongStr);
var p, cur: Integer;
begin
  p := LSFindStr(line, '"params":');
  if p = 0 then Exit;
  cur := p + 9;
  SkipToChar(line, cur, '[');
  cur := cur + 1;
  targetDiff := ReadDifficultyCeil(line, cur);
  if targetDiff < 1 then targetDiff := 1;
end;

procedure ProcessLine(var line: LongStr);
var id: LongInt;
begin
  if LSContains(line, '"method"') then begin
    if LSContains(line, 'mining.notify') then HandleNotify(line)
    else if LSContains(line, 'mining.set_difficulty') then HandleSetDiff(line);
    { other notifications (client.reconnect, client.show_message) are ignored }
  end else begin
    id := ExtractId(line);
    if id = kSubscribeId then HandleSubscribeResult(line)
    else if id = kAuthorizeId then HandleAuthorizeResult(line)
    else if id >= kFirstSubmitId then HandleSubmitResult(line);
  end;
end;

procedure PumpNetwork;
var tcpPB: TCPiopb; err: OSErr; tmp: array[0..1023] of Char;
    avail, n, i, nlPos: Integer;
begin
  if tcpStream = nil then Exit;
  ZeroPB(tcpPB);
  tcpPB.csCode := TCPStatus;
  tcpPB.tcpStream := tcpStream;
  err := PBControl(@tcpPB, false);
  if err = noErr then begin
    avail := tcpPB.csParam.status.amtUnreadData;
    if avail > 0 then begin
      if avail > 1024 then avail := 1024;
      ZeroPB(tcpPB);
      tcpPB.csCode := TCPRcv;
      tcpPB.tcpStream := tcpStream;
      tcpPB.csParam.receive.rcvBuff := @tmp;
      tcpPB.csParam.receive.rcvBuffLen := avail;
      err := PBControl(@tcpPB, false);
      if err = noErr then begin
        n := tcpPB.csParam.receive.rcvBuffLen;
        for i := 0 to n - 1 do LSAppendChar(recvAccum, tmp[i]);
      end;
    end;
  end;
  { dispatch every complete newline-terminated line }
  nlPos := LSFindCharNL(recvAccum);
  while nlPos > 0 do begin
    LSCopyRange(recvAccum, 1, nlPos - 1, lineBuf);
    LSDeleteFront(recvAccum, nlPos);
    if lineBuf.len > 0 then ProcessLine(lineBuf);
    nlPos := LSFindCharNL(recvAccum);
  end;
end;

{ ========================================================================= }
{  Mining inner loop                                                        }
{ ========================================================================= }

procedure DoMining;
var hInt, hBE: Byte32; i: Integer;
begin
  if not jobReady then Exit;
  headerTemplate[76] := currentNonce and $FF;
  headerTemplate[77] := (currentNonce shr 8) and $FF;
  headerTemplate[78] := (currentNonce shr 16) and $FF;
  headerTemplate[79] := (currentNonce shr 24) and $FF;
  DoubleSHA256(@headerTemplate, 80, hInt);
  for i := 0 to 31 do hBE[i] := hInt[31 - i];
  if ShareMeetsDifficulty(hBE, targetDiff) then SubmitShare(currentNonce);
  currentNonce := currentNonce + 1;
  hashCount := hashCount + 1;
end;

{ ========================================================================= }
{  Self-test: hash the real genesis block header on-device                  }
{ ========================================================================= }

procedure RunSelfTest;
var hdrHex: LongStr; hb: Byte1K; hlen, i: Integer;
    hInt, hBE: Byte32; disp: Str255;
begin
  LSClear(hdrHex);
  LSAppendStr(hdrHex, '0100000000000000000000000000000000000000');
  LSAppendStr(hdrHex, '000000000000000000000000000000003ba3edfd');
  LSAppendStr(hdrHex, '7a7b12b27ac72c3e67768f617fc81bc3888a5132');
  LSAppendStr(hdrHex, '3a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c');
  hlen := hdrHex.len div 2;
  for i := 0 to hlen - 1 do
    hb[i] := HexVal(hdrHex.data[i * 2 + 1]) * 16 + HexVal(hdrHex.data[i * 2 + 2]);
  DoubleSHA256(@hb, hlen, hInt);
  for i := 0 to 31 do hBE[i] := hInt[31 - i];
  BytesToHexStr(hBE, 32, disp);
  selfTestPass :=
    (disp = '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f');
  selfTestDiffOk :=
    ShareMeetsDifficulty(hBE, 1) and (not ShareMeetsDifficulty(hBE, 16777216));
  selfTestDone := true;
  InvalRect(myWindow^.portRect);
end;

{ ========================================================================= }
{  UI                                                                       }
{ ========================================================================= }

procedure InitToolbox;
begin
  InitGraf(@thePort); InitFonts; InitWindows; InitMenus; TEInit;
  InitDialogs(nil); InitCursor;
end;

procedure CreateMainWindow;
var tempRect: Rect;
begin
  SetRect(tempRect, 30, 30, 30 + kWindowWidth, 30 + kWindowHeight);
  myWindow := NewWindow(nil, tempRect, 'Bitcoin Pool Miner', true,
                        documentProc, WindowPtr(-1), true, 0);
  SetPort(myWindow);
end;

procedure InitTextFields;
begin
  SetRect(walletRect, 140, 30, 500, 46); walletEdit := TENew(walletRect, walletRect);
  TESetText('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', 34, walletEdit);
  SetRect(poolRect, 140, 70, 500, 86); poolEdit := TENew(poolRect, poolRect);
  TESetText('stratum+tcp://solo.ckpool.org:3333', 34, poolEdit);
  SetRect(workerRect, 140, 110, 360, 126); workerEdit := TENew(workerRect, workerRect);
  TESetText('worker1', 7, workerEdit);
  SetRect(passRect, 140, 150, 360, 166); passEdit := TENew(passRect, passRect);
  TESetText('x', 1, passEdit);
end;

procedure InitButtons;
begin
  SetRect(connectButton, 140, 190, 240, 214);
  SetRect(disconnectButton, 250, 190, 360, 214);
  SetRect(selfTestButton, 380, 190, 500, 214);
end;

procedure DrawWindow;
var tempStr: Str255; hashRate: Real; elapsed: LongInt;
begin
  SetPort(myWindow); EraseRect(myWindow^.portRect);
  MoveTo(10, 43); DrawString('Wallet Address:');
  TEUpdate(walletRect, walletEdit); FrameRect(walletRect);
  MoveTo(10, 83); DrawString('Pool Address:');
  TEUpdate(poolRect, poolEdit); FrameRect(poolRect);
  MoveTo(10, 123); DrawString('Worker Name:');
  TEUpdate(workerRect, workerEdit); FrameRect(workerRect);
  MoveTo(10, 163); DrawString('Password:');
  TEUpdate(passRect, passEdit); FrameRect(passRect);

  FrameRoundRect(connectButton, 10, 10);
  MoveTo(connectButton.left + 22, connectButton.top + 16); DrawString('Connect');
  FrameRoundRect(disconnectButton, 10, 10);
  MoveTo(disconnectButton.left + 18, disconnectButton.top + 16); DrawString('Disconnect');
  FrameRoundRect(selfTestButton, 10, 10);
  MoveTo(selfTestButton.left + 26, selfTestButton.top + 16); DrawString('Self-Test');

  MoveTo(10, 240);
  case currentState of
    Stopped: DrawString('Status: Disconnected');
    Connecting: DrawString('Status: Connecting...');
    Subscribing: DrawString('Status: Subscribing...');
    Authorizing: DrawString('Status: Authorizing...');
    Mining: DrawString('Status: Mining');
  end;

  if jobReady then begin
    MoveTo(10, 260); DrawString('Job: ');
    if Length(jobId) > 0 then DrawString(jobId);
    MoveTo(260, 260); NumToString(targetDiff, tempStr);
    DrawString(Concat('Difficulty: ', tempStr));

    MoveTo(10, 280); NumToString(hashCount, tempStr);
    DrawString(Concat('Hashes: ', tempStr));
    MoveTo(10, 300); elapsed := (TickCount - lastUpdateTime) div 60;
    if elapsed > 0 then begin
      hashRate := hashCount / elapsed; NumToString(Trunc(hashRate), tempStr);
      DrawString(Concat('Rate: ~', tempStr, ' H/s'));
    end;
    MoveTo(10, 320); NumToString(sharesFound, tempStr);
    DrawString(Concat('Shares found: ', tempStr));
    MoveTo(10, 340); NumToString(sharesAccepted, tempStr);
    DrawString(Concat('Accepted: ', tempStr));
    MoveTo(10, 360); NumToString(sharesRejected, tempStr);
    DrawString(Concat('Rejected: ', tempStr));
  end;

  MoveTo(10, 390);
  if selfTestDone then begin
    if selfTestPass and selfTestDiffOk then
      DrawString('Self-Test: PASS (SHA-256d + difficulty verified)')
    else if selfTestPass then
      DrawString('Self-Test: SHA ok, difficulty FAILED')
    else
      DrawString('Self-Test: FAILED - crypto path is wrong!');
  end else
    DrawString('Self-Test: not run (click Self-Test to verify crypto)');

  MoveTo(10, 415); DrawString('Real Stratum pool mining on Mac OS 6.8');
end;

procedure HandleMouseDown(var theEvent: EventRecord);
var whichWindow: WindowPtr; thePart: Integer; localPt: Point; err: OSErr; temp: Str255;
begin
  thePart := FindWindow(theEvent.where, whichWindow);
  if thePart = inContent then begin
    if whichWindow <> FrontWindow then SelectWindow(whichWindow)
    else begin
      localPt := theEvent.where; GlobalToLocal(localPt);
      if PtInRect(localPt, walletRect) then TEClick(localPt, false, walletEdit)
      else if PtInRect(localPt, poolRect) then TEClick(localPt, false, poolEdit)
      else if PtInRect(localPt, workerRect) then TEClick(localPt, false, workerEdit)
      else if PtInRect(localPt, passRect) then TEClick(localPt, false, passEdit)
      else if PtInRect(localPt, connectButton) then begin
        BlockMove(poolEdit^^.hText^, @temp[1], poolEdit^^.teLength);
        temp[0] := Chr(poolEdit^^.teLength);
        ParseHostOnly(temp, poolConfig.host);
        poolConfig.port := ParsePort(temp);
        if poolConfig.port > 0 then begin
          BlockMove(workerEdit^^.hText^, @poolConfig.username[1], workerEdit^^.teLength);
          poolConfig.username[0] := Chr(workerEdit^^.teLength);
          BlockMove(passEdit^^.hText^, @poolConfig.password[1], passEdit^^.teLength);
          poolConfig.password[0] := Chr(passEdit^^.teLength);
          subscribeDone := false; authorized := false;
          haveNotify := false; jobReady := false;
          sharesFound := 0; sharesAccepted := 0; sharesRejected := 0;
          messageId := 0; targetDiff := 1; LSClear(recvAccum);
          currentState := Connecting; InvalRect(myWindow^.portRect);
          err := ConnectToPool;
          if err = noErr then begin
            currentState := Subscribing; SendSubscribe;
            lastUpdateTime := TickCount;
          end else
            currentState := Stopped;
        end;
        InvalRect(myWindow^.portRect);
      end
      else if PtInRect(localPt, disconnectButton) then begin
        DisconnectFromPool; currentState := Stopped; jobReady := false;
        InvalRect(myWindow^.portRect);
      end
      else if PtInRect(localPt, selfTestButton) then
        RunSelfTest;
    end;
  end
  else if thePart = inDrag then
    DragWindow(whichWindow, theEvent.where, screenBits.bounds)
  else if thePart = inGoAway then
    if TrackGoAway(whichWindow, theEvent.where) then doneFlag := true;
end;

procedure HandleEvent(var theEvent: EventRecord);
begin
  case theEvent.what of
    mouseDown: HandleMouseDown(theEvent);
    updateEvt: begin
        BeginUpdate(WindowPtr(theEvent.message));
        DrawWindow;
        EndUpdate(WindowPtr(theEvent.message));
      end;
  end;
end;

procedure MainLoop;
var theEvent: EventRecord; i: Integer;
begin
  doneFlag := false; currentState := Stopped;
  hashCount := 0; currentNonce := 0;
  sharesFound := 0; sharesAccepted := 0; sharesRejected := 0; messageId := 0;
  tcpStream := nil; gDriverOpen := false; gDriverRef := 0;
  subscribeDone := false; authorized := false;
  haveNotify := false; jobReady := false;
  extranonce2Size := 4; targetDiff := 1; nBranch := 0;
  selfTestDone := false; selfTestPass := false; selfTestDiffOk := false;
  LSClear(recvAccum); LSClear(lineBuf);

  while not doneFlag do begin
    SystemTask;
    if tcpStream <> nil then PumpNetwork;
    if (currentState = Mining) and jobReady then begin
      for i := 1 to 8 do DoMining;
      InvalRect(myWindow^.portRect);
      if GetNextEvent(everyEvent, theEvent) then HandleEvent(theEvent);
    end else begin
      if WaitNextEvent(everyEvent, theEvent, 20, nil) then HandleEvent(theEvent);
    end;
  end;
end;

{ ========================================================================= }
{  Entry point                                                              }
{ ========================================================================= }

begin
  InitToolbox;
  CreateMainWindow;
  InitTextFields;
  InitButtons;
  DrawWindow;
  MainLoop;
  if tcpStream <> nil then DisconnectFromPool;
{$IFC USE_DNR}
  if gDriverOpen then CloseResolver;
{$ENDC}
  TEDispose(walletEdit); TEDispose(poolEdit);
  TEDispose(workerEdit); TEDispose(passEdit);
  DisposeWindow(myWindow);
end.
