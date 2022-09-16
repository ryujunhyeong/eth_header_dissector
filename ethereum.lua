-- Ethereum Node Discovery Protocol/v5 Dissector plugin
-- by JunHyeong Ryu
-- date 2022 .05
-- version 0.1


local ethereum_protocol = Proto("Ethereum", "ETHEREUM PROTOCOL")
local ETHEREUM_PORT = 30303
packet_type = {
  [0] = "Ordinary Message Packet",
  [1] = "WHOAREYOU Packet",
  [2] = "HandShake Message Packet",
  [3] = NULL
}


-- Ethereum header fields
local f  = ethereum_protocol.fields
f.maskingiv = ProtoField.bytes("ethereum.hash", "MASKING-IV", base.NONE) -- 16byte
f.protocolid = ProtoField.bytes("ethereum.sign", "Protocol-ID", base.NONE) -- 65byte
f.version = ProtoField.bytes("ethereum.sign", "Version", base.NONE) -- 65byte
f.flag = ProtoField.uint8("ethereum.ptype", "Flag", base.DEC, packet_type) -- 1byte
f.nonce = ProtoField.bytes("ethereum.data", "Nonce", base.NONE) -- Temporary payload data
f.authsize = ProtoField.bytes("ethereum.data", "Authsize", base.NONE) -- Temporary payload data
f.data = ProtoField.bytes("ethereum.data", "Message data", base.NONE) -- Temporary payload data
f.srcid = ProtoField.bytes("ethereum.data", "Src-ID", base.NONE) -- Temporary payload data
f.idnonce = ProtoField.bytes("ethereum.data", "ID-Nonce", base.NONE) -- Temporary payload data
f.enrseq = ProtoField.bytes("ethereum.data", "Enr-Seq", base.NONE) -- Temporary payload data
f.sigs = ProtoField.bytes("ethereum.data", "sig-s", base.NONE) -- Temporary payload data
f.ks = ProtoField.bytes("ethereum.data", "k-s", base.NONE) -- Temporary payload data
f.idsignature = ProtoField.bytes("ethereum.data", "id-signature", base.NONE) -- Temporary payload data
f.ephemeralpubkey = ProtoField.bytes("ethereum.data", "ephemeral-pubkey", base.NONE) -- Temporary payload data
f.record = ProtoField.bytes("ethereum.data", "record", base.NONE) -- Temporary payload data
--f.trash_data = ProtoField.bytes("ethereum.", "Payload Data", base.NONE) -- Temporary payload data

-- PingV4 fields
local ping = ethereum_protocol.fields
--ping.version = ProtoField.uint8("ethereum.version", "Version", base.DEC) -- 1byte

-- ETHEREUM dissector function 
function ethereum_protocol.dissector(buffer, pinfo, tree)
  local offset = 0 -- 현재 가리키는 위치
  local len = buffer:len() -- 총 길이
  local type = buffer(offset+24, 1):uint() -- 타입의 1바이트를 정의하는 부분

  local maintree = tree:add(ethereum_protocol, buffer(), packet_type[type])

  -- 해쉬의 각 바이트 별로 오프셋 1씩 차이남
  -- header = hash + sign + packet_type
  if type==0 or type==1 or type==2 then
    maintree:add(f.maskingiv, buffer(offset, 16))
    offset = offset + 16

    maintree:add(f.protocolid, buffer(offset, 6))
    offset = offset + 6

    maintree:add(f.version, buffer(offset, 2))
    offset = offset + 2

    maintree:add(f.flag, buffer(offset, 1))
    offset = offset + 1

    maintree:add(f.nonce, buffer(offset, 12))
    offset = offset + 12

    maintree:add(f.authsize, buffer(offset, 2))
    offset = offset + 2
  end
 
  if type == 0 then 
    maintree:add(f.srcid, buffer(offset, 32))
    offset = offset + 32
    maintree:add(f.data, buffer(offset, len-offset))
    -- set the protocol name
    local protocol_str = "Ethereum";-- 메인 화면에 Protocol 부분에 나오는 값 부분
    pinfo.cols.protocol = protocol_str
    -- set the info column name
    local info_str = packet_type[type];-- 메인 화면에 Info 부분에 나오는 값 부분
    pinfo.cols.info = info_str

  elseif type == 1 then
    -- ping version : 1byte
    maintree:add(f.idnonce, buffer(offset, 16))
    offset = offset + 16
    maintree:add(f.enrseq, buffer(offset, len-offset))

    -- set the protocol name
    local protocol_str = "Ethereum";-- 메인 화면에 Protocol 부분에 나오는 값 부분
    pinfo.cols.protocol = protocol_str
    -- set the info column namesss
    local info_str = packet_type[type];-- 메인 화면에 Info 부분에 나오는 값 부분
    pinfo.cols.info = info_str

  elseif type == 2 then
    -- ping version : 1byte
    local sig_s = buffer(71, 1):uint() -- 타입의 1바이트를 정의하는 부분
    local k_s = buffer(72, 1):uint() -- 타입의 1바이트를 정의하는 부분
    local auth_size_front = buffer(37, 1):uint() -- 타입의 1바이트를 정의하는 부분
    local auth_size_back = buffer(38, 1):uint() -- 타입의 1바이트를 정의하는 부분
    maintree:add(f.srcid, buffer(offset, 32))
    offset = offset + 32
    maintree:add(f.sigs, buffer(offset, 1))
    offset = offset + 1
    maintree:add(f.ks, buffer(offset, 1))
    offset = offset + 1
    maintree:add(f.idsignature, buffer(offset, (sig_s/10)*16+sig_s%10))
    offset = offset + sig_s
    maintree:add(f.ephemeralpubkey, buffer(offset, k_s))
    offset = offset + k_s
    maintree:add(f.record, buffer(offset, auth_size_front*100+auth_size_back-k_s-sig_s))
    offset = offset + auth_size_front*100+auth_size_back-k_s-sig_s
    -- set the protocol name
    local protocol_str = "Ethereum";-- 메인 화면에 Protocol 부분에 나오는 값 부분
    pinfo.cols.protocol = protocol_str
    -- set the info column name
    local info_str = packet_type[type];-- 메인 화면에 Info 부분에 나오는 값 부분
    pinfo.cols.info = info_str
  end
end
-- use the original dissector so we can still get to it
DissectorTable.get("udp.port"):add(ETHEREUM_PORT, ethereum_protocol)