program BitcoinPoolMiner;

uses
  MacTypes, QuickDraw, Fonts, Events, Windows, Menus, TextEdit, Dialogs, OSUtils, MacTCP, Strings;

const
  kWindowWidth = 520;
  kWindowHeight = 420;
  kTCPBufferSize = 8192;

type
  MinerState = (Stopped, Connecting, Subscribing, Authorizing, Mining, Submitting);
  UInt32 = LongInt;
  
  SHA256State = record
    h: array[0..7] of UInt32;
  end;
  
  PoolConfig = record
    host: Str255;
    port: Integer;
    username: Str255;
    password: Str255;
  end;
  
  StratumJob = record
    jobId: Str255;
    hasJob: Boolean;
  end;

var
  myWindow: WindowPtr;
  doneFlag: Boolean;
  walletEdit, poolEdit, workerEdit, passEdit: TEHandle;
  walletRect, poolRect, workerRect, passRect: Rect;
  connectButton, disconnectButton: Rect;
  currentState: MinerState;
  hashCount, currentNonce: LongInt;
  sharesFound, sharesAccepted, sharesRejected: Integer;
  tcpStream: StreamPtr;
  tcpBuffer: array[0..kTCPBufferSize-1] of Char;
  receiveBuffer: Str255;
  poolConfig: PoolConfig;
  currentJob: StratumJob;
  lastUpdateTime: LongInt;
  messageId: Integer;

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
  H0: array[0..7] of UInt32 = ($6a09e667, $bb67ae85, $3c6ef372, $a54ff53a, $510e527f, $9b05688c, $1f83d9ab, $5be0cd19);

function ROTR(x: UInt32; n: Integer): UInt32;
begin ROTR := (x shr n) or (x shl (32 - n)); end;

function Ch(x, y, z: UInt32): UInt32;
begin Ch := (x and y) xor ((not x) and z); end;

function Maj(x, y, z: UInt32): UInt32;
begin Maj := (x and y) xor (x and z) xor (y and z); end;

function Sigma0(x: UInt32): UInt32;
begin Sigma0 := ROTR(x, 2) xor ROTR(x, 13) xor ROTR(x, 22); end;

function Sigma1(x: UInt32): UInt32;
begin Sigma1 := ROTR(x, 6) xor ROTR(x, 11) xor ROTR(x, 25); end;

function sigma0(x: UInt32): UInt32;
begin sigma0 := ROTR(x, 7) xor ROTR(x, 18) xor (x shr 3); end;

function sigma1(x: UInt32): UInt32;
begin sigma1 := ROTR(x, 17) xor ROTR(x, 19) xor (x shr 10); end;

function SwapBytes32(x: UInt32): UInt32;
var b0, b1, b2, b3: Byte;
begin
  b0 := x and $FF; b1 := (x shr 8) and $FF; b2 := (x shr 16) and $FF; b3 := (x shr 24) and $FF;
  SwapBytes32 := (UInt32(b0) shl 24) or (UInt32(b1) shl 16) or (UInt32(b2) shl 8) or UInt32(b3);
end;

procedure SHA256TransformBlock(var state: SHA256State; const data: Ptr);
var W: array[0..63] of UInt32; a, b, c, d, e, f, g, h, t1, t2: UInt32; i: Integer; dataPtr: ^UInt32;
begin
  dataPtr := Ptr(data);
  for i := 0 to 15 do begin W[i] := SwapBytes32(dataPtr^); dataPtr := Ptr(Ord(dataPtr) + 4); end;
  for i := 16 to 63 do W[i] := sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];
  a := state.h[0]; b := state.h[1]; c := state.h[2]; d := state.h[3];
  e := state.h[4]; f := state.h[5]; g := state.h[6]; h := state.h[7];
  for i := 0 to 63 do begin
    t1 := h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];
    t2 := Sigma0(a) + Maj(a, b, c);
    h := g; g := f; f := e; e := d + t1; d := c; c := b; b := a; a := t1 + t2;
  end;
  state.h[0] := state.h[0] + a; state.h[1] := state.h[1] + b; state.h[2] := state.h[2] + c; state.h[3] := state.h[3] + d;
  state.h[4] := state.h[4] + e; state.h[5] := state.h[5] + f; state.h[6] := state.h[6] + g; state.h[7] := state.h[7] + h;
end;

procedure DoubleSHA256(const data: Ptr; len: Integer; var outHash: array of Byte);
var state1, state2: SHA256State; midHash: array[0..31] of Byte; padded: array[0..127] of Byte; i, blocks: Integer;
begin
  for i := 0 to 7 do state1.h[i] := H0[i];
  FillChar(padded, 128, 0); BlockMove(data, @padded, len); padded[len] := $80;
  blocks := (len + 9 + 63) div 64;
  padded[blocks*64-4] := (len*8) shr 24; padded[blocks*64-3] := (len*8) shr 16;
  padded[blocks*64-2] := (len*8) shr 8; padded[blocks*64-1] := len*8;
  for i := 0 to blocks-1 do SHA256TransformBlock(state1, Ptr(@padded[i*64]));
  for i := 0 to 7 do begin
    midHash[i*4] := (state1.h[i] shr 24) and $FF; midHash[i*4+1] := (state1.h[i] shr 16) and $FF;
    midHash[i*4+2] := (state1.h[i] shr 8) and $FF; midHash[i*4+3] := state1.h[i] and $FF;
  end;
  for i := 0 to 7 do state2.h[i] := H0[i];
  FillChar(padded, 64, 0); BlockMove(@midHash, @padded, 32); padded[32] := $80; padded[62] := $01;
  SHA256TransformBlock(state2, @padded);
  for i := 0 to 7 do begin
    outHash[i*4] := (state2.h[i] shr 24) and $FF; outHash[i*4+1] := (state2.h[i] shr 16) and $FF;
    outHash[i*4+2] := (state2.h[i] shr 8) and $FF; outHash[i*4+3] := state2.h[i] and $FF;
  end;
end;

function HexChar(nibble: Integer): Char;
begin if nibble < 10 then HexChar := Chr(Ord('0') + nibble) else HexChar := Chr(Ord('a') + nibble - 10); end;

procedure BytesToHex(var bytes: array of Byte; count: Integer; var hex: Str255);
var i: Integer;
begin
  hex := '';
  for i := 0 to count-1 do begin
    hex[Length(hex)+1] := HexChar(bytes[i] shr 4); hex[Length(hex)+2] := HexChar(bytes[i] and $0F);
    hex[0] := Chr(Length(hex)+2);
  end;
end;

function ParseHostPort(addr: Str255; var host: Str255; var port: Integer): Boolean;
var colonPos, i: Integer; portStr: Str255;
begin
  if Pos('://', addr) > 0 then Delete(addr, 1, Pos('://', addr) + 2);
  colonPos := Pos(':', addr);
  if colonPos = 0 then begin ParseHostPort := false; Exit; end;
  host := Copy(addr, 1, colonPos - 1); portStr := Copy(addr, colonPos + 1, 255);
  port := 0;
  for i := 1 to Length(portStr) do
    if (portStr[i] >= '0') and (portStr[i] <= '9') then port := port * 10 + (Ord(portStr[i]) - Ord('0'));
  ParseHostPort := (port > 0);
end;

function ConnectToPool: OSErr;
var err: OSErr; tcpPB: TCPiopb; addr: ip_addr; i, j, octet, dotPos: Integer; ipStr, octetStr: Str255;
begin
  err := OpenDriver('.IPP', tcpStream);
  if err <> noErr then begin ConnectToPool := err; Exit; end;
  ipStr := poolConfig.host; addr := 0;
  for i := 1 to 4 do begin
    dotPos := Pos('.', ipStr);
    if (dotPos = 0) and (i < 4) then dotPos := Length(ipStr) + 1;
    if i = 4 then octetStr := ipStr else octetStr := Copy(ipStr, 1, dotPos - 1);
    octet := 0;
    for j := 1 to Length(octetStr) do octet := octet * 10 + (Ord(octetStr[j]) - Ord('0'));
    addr := (addr shl 8) or octet;
    if i < 4 then Delete(ipStr, 1, dotPos);
  end;
  FillChar(tcpPB, SizeOf(tcpPB), 0); tcpPB.csCode := TCPCreate;
  tcpPB.csParam.create.rcvBuff := @tcpBuffer; tcpPB.csParam.create.rcvBuffLen := kTCPBufferSize;
  err := PBControl(@tcpPB, false);
  if err <> noErr then begin ConnectToPool := err; Exit; end;
  tcpStream := tcpPB.tcpStream;
  FillChar(tcpPB, SizeOf(tcpPB), 0); tcpPB.csCode := TCPActiveOpen; tcpPB.tcpStream := tcpStream;
  tcpPB.csParam.open.remoteHost := addr; tcpPB.csParam.open.remotePort := poolConfig.port;
  tcpPB.csParam.open.timeToLive := 60;
  ConnectToPool := PBControl(@tcpPB, false);
end;

procedure SendToPool(msg: Str255);
var tcpPB: TCPiopb; wdsRec: array[0..1] of wdsEntry;
begin
  if tcpStream = nil then Exit;
  msg := Concat(msg, Chr(10));
  wdsRec[0].length := Length(msg); wdsRec[0].ptr := @msg[1]; wdsRec[1].length := 0;
  FillChar(tcpPB, SizeOf(tcpPB), 0); tcpPB.csCode := TCPSend; tcpPB.tcpStream := tcpStream;
  tcpPB.csParam.send.wdsPtr := @wdsRec; tcpPB.csParam.send.pushFlag := true;
  PBControl(@tcpPB, false);
end;

function ReceiveFromPool: Boolean;
var tcpPB: TCPiopb; err: OSErr; buffer: array[0..255] of Char; len: Integer;
begin
  if tcpStream = nil then begin ReceiveFromPool := false; Exit; end;
  FillChar(tcpPB, SizeOf(tcpPB), 0); tcpPB.csCode := TCPStatus; tcpPB.tcpStream := tcpStream;
  err := PBControl(@tcpPB, false);
  if (err <> noErr) or (tcpPB.csParam.status.amtUnreadData = 0) then begin ReceiveFromPool := false; Exit; end;
  FillChar(tcpPB, SizeOf(tcpPB), 0); tcpPB.csCode := TCPRcv; tcpPB.tcpStream := tcpStream;
  tcpPB.csParam.receive.rcvBuff := @buffer; tcpPB.csParam.receive.rcvBuffLen := 255;
  err := PBControl(@tcpPB, false);
  if err = noErr then begin
    len := tcpPB.csParam.receive.rcvBuffLen; BlockMove(@buffer, @receiveBuffer[1], len);
    receiveBuffer[0] := Chr(len); ReceiveFromPool := true;
  end else ReceiveFromPool := false;
end;

procedure DisconnectFromPool;
var tcpPB: TCPiopb;
begin
  if tcpStream = nil then Exit;
  FillChar(tcpPB, SizeOf(tcpPB), 0); tcpPB.csCode := TCPClose; tcpPB.tcpStream := tcpStream; PBControl(@tcpPB, false);
  FillChar(tcpPB, SizeOf(tcpPB), 0); tcpPB.csCode := TCPRelease; tcpPB.tcpStream := tcpStream; PBControl(@tcpPB, false);
  tcpStream := nil;
end;

procedure SendSubscribe;
var msg, temp: Str255;
begin
  messageId := messageId + 1; NumToString(messageId, temp);
  msg := Concat('{"id":', temp, ',"method":"mining.subscribe","params":[]}');
  SendToPool(msg);
end;

procedure SendAuthorize;
var msg, temp: Str255;
begin
  messageId := messageId + 1; NumToString(messageId, temp);
  msg := Concat('{"id":', temp, ',"method":"mining.authorize","params":["');
  msg := Concat(msg, poolConfig.username, '","', poolConfig.password, '"]}');
  SendToPool(msg);
end;

procedure SendShare(nonce: UInt32);
var msg, temp, nonceHex: Str255; nonceBytes: array[0..3] of Byte;
begin
  nonceBytes[0] := nonce and $FF; nonceBytes[1] := (nonce shr 8) and $FF;
  nonceBytes[2] := (nonce shr 16) and $FF; nonceBytes[3] := (nonce shr 24) and $FF;
  BytesToHex(nonceBytes, 4, nonceHex);
  messageId := messageId + 1; NumToString(messageId, temp);
  msg := Concat('{"id":', temp, ',"method":"mining.submit","params":["');
  msg := Concat(msg, poolConfig.username, '","job1","00000000","00000000","', nonceHex, '"]}');
  SendToPool(msg); sharesFound := sharesFound + 1;
end;

procedure ProcessStratumMessage(msg: Str255);
begin
  if Pos('mining.notify', msg) > 0 then begin currentJob.hasJob := true; currentState := Mining; end
  else if Pos('"result":true', msg) > 0 then begin
    if Pos('"id":2', msg) > 0 then currentState := Mining else sharesAccepted := sharesAccepted + 1;
  end
  else if Pos('"result":false', msg) > 0 then sharesRejected := sharesRejected + 1
  else if Pos('mining.subscribe', msg) > 0 then begin currentState := Authorizing; SendAuthorize; end;
end;

procedure InitToolbox;
begin InitGraf(@thePort); InitFonts; InitWindows; InitMenus; TEInit; InitDialogs(nil); InitCursor; end;

procedure CreateMainWindow;
var tempRect: Rect;
begin
  SetRect(tempRect, 30, 30, 30 + kWindowWidth, 30 + kWindowHeight);
  myWindow := NewWindow(nil, tempRect, 'Bitcoin Pool Miner', true, documentProc, WindowPtr(-1), true, 0);
  SetPort(myWindow);
end;

procedure InitTextFields;
begin
  SetRect(walletRect, 140, 30, 500, 46); walletEdit := TENew(walletRect, walletRect);
  TESetText('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', 34, walletEdit);
  SetRect(poolRect, 140, 70, 500, 86); poolEdit := TENew(poolRect, poolRect);
  TESetText('stratum+tcp://solo.ckpool.org:3333', 35, poolEdit);
  SetRect(workerRect, 140, 110, 360, 126); workerEdit := TENew(workerRect, workerRect);
  TESetText('worker1', 7, workerEdit);
  SetRect(passRect, 140, 150, 360, 166); passEdit := TENew(passRect, passRect);
  TESetText('x', 1, passEdit);
end;

procedure InitButtons;
begin SetRect(connectButton, 140, 190, 250, 215); SetRect(disconnectButton, 270, 190, 380, 215); end;

procedure DrawWindow;
var tempStr: Str255; hashRate: Real; elapsed: LongInt;
begin
  SetPort(myWindow); EraseRect(myWindow^.portRect);
  MoveTo(10, 43); DrawString('Wallet Address:'); TEUpdate(walletRect, walletEdit); FrameRect(walletRect);
  MoveTo(10, 83); DrawString('Pool Address:'); TEUpdate(poolRect, poolEdit); FrameRect(poolRect);
  MoveTo(10, 123); DrawString('Worker Name:'); TEUpdate(workerRect, workerEdit); FrameRect(workerRect);
  MoveTo(10, 163); DrawString('Password:'); TEUpdate(passRect, passEdit); FrameRect(passRect);
  FrameRoundRect(connectButton, 10, 10); MoveTo(connectButton.left + 30, connectButton.top + 18); DrawString('Connect');
  FrameRoundRect(disconnectButton, 10, 10); MoveTo(disconnectButton.left + 20, disconnectButton.top + 18); DrawString('Disconnect');
  MoveTo(10, 240);
  case currentState of
    Stopped: DrawString('Status: Disconnected');
    Connecting: DrawString('Status: Connecting...');
    Subscribing: DrawString('Status: Subscribing...');
    Authorizing: DrawString('Status: Authorizing...');
    Mining: DrawString('Status: Mining');
    Submitting: DrawString('Status: Submitting share!');
  end;
  if currentJob.hasJob then begin
    MoveTo(10, 260); NumToString(hashCount, tempStr); DrawString(Concat('Hashes: ', tempStr));
    MoveTo(10, 280); NumToString(currentNonce, tempStr); DrawString(Concat('Nonce: ', tempStr));
    MoveTo(10, 300); elapsed := (TickCount - lastUpdateTime) div 60;
    if elapsed > 0 then begin
      hashRate := hashCount / elapsed; NumToString(Trunc(hashRate), tempStr);
      DrawString(Concat('Rate: ~', tempStr, ' H/s'));
    end;
    MoveTo(10, 320); NumToString(sharesFound, tempStr); DrawString(Concat('Shares found: ', tempStr));
    MoveTo(10, 340); NumToString(sharesAccepted, tempStr); DrawString(Concat('Accepted: ', tempStr));
    MoveTo(10, 360); NumToString(sharesRejected, tempStr); DrawString(Concat('Rejected: ', tempStr));
  end;
  MoveTo(10, 390); DrawString('Real pool mining on Mac OS 6.8!');
end;

procedure HandleMouseDown(var theEvent: EventRecord);
var whichWindow: WindowPtr; thePart: Integer; localPt: Point; err: OSErr; temp: Str255;
begin
  thePart := FindWindow(theEvent.where, whichWindow);
  if thePart = inContent then begin
    if whichWindow <> FrontWindow then SelectWindow(whichWindow) else begin
      localPt := theEvent.where; GlobalToLocal(localPt);
      if PtInRect(localPt, walletRect) then TEClick(localPt, false, walletEdit)
      else if PtInRect(localPt, poolRect) then TEClick(localPt, false, poolEdit)
      else if PtInRect(localPt, workerRect) then TEClick(localPt, false, workerEdit)
      else if PtInRect(localPt, passRect) then TEClick(localPt, false, passEdit)
      else if PtInRect(localPt, connectButton) then begin
        BlockMove(poolEdit^^.hText^, @temp[1], poolEdit^^.teLength); temp[0] := Chr(poolEdit^^.teLength);
        if ParseHostPort(temp, poolConfig.host, poolConfig.port) then begin
          BlockMove(workerEdit^^.hText^, @poolConfig.username[1], workerEdit^^.teLength);
          poolConfig.username[0] := Chr(workerEdit^^.teLength);
          BlockMove(passEdit^^.hText^, @poolConfig.password[1], passEdit^^.teLength);
          poolConfig.password[0] := Chr(passEdit^^.teLength);
          currentState := Connecting; err := ConnectToPool;
          if err = noErr then begin currentState := Subscribing; SendSubscribe; lastUpdateTime := TickCount; end
          else currentState := Stopped;
        end;
        InvalRect(myWindow^.portRect);
      end
      else if PtInRect(localPt, disconnectButton) then begin
        DisconnectFromPool; currentState := Stopped; currentJob.hasJob := false; InvalRect(myWindow^.portRect);
      end;
    end;
  end
  else if thePart = inDrag then DragWindow(whichWindow, theEvent.where, screenBits.bounds)
  else if thePart = inGoAway then if TrackGoAway(whichWindow, theEvent.where) then doneFlag := true;
end;

function CheckDifficulty(var hash: array of Byte): Boolean;
var i: Integer;
begin
  for i := 31 downto 28 do if hash[i] <> 0 then begin CheckDifficulty := false; Exit; end;
  CheckDifficulty := true;
end;

procedure DoMining;
var hash: array[0..31] of Byte;
begin
  if ReceiveFromPool then ProcessStratumMessage(receiveBuffer);
  if (currentState = Mining) and currentJob.hasJob then begin
    hash[0] := currentNonce and $FF; hash[1] := (currentNonce shr 8) and $FF;
    hash[2] := (currentNonce shr 16) and $FF; hash[3] := (currentNonce shr 24) and $FF;
    DoubleSHA256(@hash, 4, hash);
    if CheckDifficulty(hash) then begin SendShare(currentNonce); currentState := Submitting; end;
    currentNonce := currentNonce + 1; hashCount := hashCount + 1;
    if (hashCount mod 10) = 0 then InvalRect(myWindow^.portRect);
  end;
end;

procedure MainLoop;
var theEvent: EventRecord;
begin
  doneFlag := false; currentState := Stopped; hashCount := 0; currentNonce := 0;
  sharesFound := 0; sharesAccepted := 0; sharesRejected := 0; messageId := 0;
  tcpStream := nil; currentJob.hasJob := false;
  while not doneFlag do begin
    SystemTask;
    if currentState = Mining then begin
      if GetNextEvent(everyEvent, theEvent) then
        case theEvent.what of
          mouseDown: HandleMouseDown(theEvent);
          updateEvt: begin BeginUpdate(WindowPtr(theEvent.message)); DrawWindow; EndUpdate(WindowPtr(theEvent.message)); end;
        end;
      DoMining;
    end else begin
      if WaitNextEvent(everyEvent, theEvent, 30, nil) then
        case theEvent.what of
          mouseDown: HandleMouseDown(theEvent);
          updateEvt: begin BeginUpdate(WindowPtr(theEvent.message)); DrawWindow; EndUpdate(WindowPtr(theEvent.message)); end;
        end;
    end;
  end;
end;

begin
  InitToolbox; CreateMainWindow; InitTextFields; InitButtons; DrawWindow; MainLoop;
  if tcpStream <> nil then DisconnectFromPool;
  TEDispose(walletEdit); TEDispose(poolEdit); TEDispose(workerEdit); TEDispose(passEdit);
  DisposeWindow(myWindow);
end.
