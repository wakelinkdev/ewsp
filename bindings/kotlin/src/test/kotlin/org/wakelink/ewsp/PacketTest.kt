/**
 * EWSP Core - Packet Protocol v1.0 Unit Tests
 * 
 * Tests for Protocol v1.0 packet structure and blockchain chaining.
 * Uses mock Packet implementation for unit testing.
 * 
 * @author deadboizxc
 * @version 1.0.0
 */
package org.wakelink.ewsp

import kotlin.test.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerialName
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class PacketTest {
    
    private val json = Json { 
        ignoreUnknownKeys = true
        encodeDefaults = true
        isLenient = true
    }
    
    companion object {
        const val GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"
        const val PROTOCOL_VERSION = "1.0"
    }
    
    // ============================================================================
    // Protocol v1.0 Packet Structure Tests
    // ============================================================================
    
    @Test
    fun `OuterPacketV2 serializes correctly`() {
        val packet = OuterPacketV2(
            v = "1.0",
            id = "WL12345678",
            seq = 1,
            prev = GENESIS_HASH,
            p = "encrypted_payload_hex",
            sig = "hmac_signature_hex"
        )
        
        val jsonStr = json.encodeToString(packet)
        
        assertTrue(jsonStr.contains("\"v\":\"1.0\""))
        assertTrue(jsonStr.contains("\"id\":\"WL12345678\""))
        assertTrue(jsonStr.contains("\"seq\":1"))
        assertTrue(jsonStr.contains("\"prev\":"))
        assertTrue(jsonStr.contains("\"p\":"))
        assertTrue(jsonStr.contains("\"sig\":"))
    }
    
    @Test
    fun `OuterPacketV2 deserializes correctly`() {
        val jsonStr = """
            {
                "v": "1.0",
                "id": "WL87654321",
                "seq": 42,
                "prev": "$GENESIS_HASH",
                "p": "payload_here",
                "sig": "signature_here"
            }
        """.trimIndent()
        
        val packet = json.decodeFromString<OuterPacketV2>(jsonStr)
        
        assertEquals("1.0", packet.v)
        assertEquals("WL87654321", packet.id)
        assertEquals(42, packet.seq)
        assertEquals(GENESIS_HASH, packet.prev)
        assertEquals("payload_here", packet.p)
        assertEquals("signature_here", packet.sig)
    }
    
    @Test
    fun `InnerPacketV2 serializes correctly`() {
        val inner = InnerPacketV2(
            cmd = "wake",
            d = mapOf("mac" to "AA:BB:CC:DD:EE:FF"),
            rid = "X7K2M9P1"
        )
        
        val jsonStr = json.encodeToString(inner)
        
        assertTrue(jsonStr.contains("\"cmd\":\"wake\""))
        assertTrue(jsonStr.contains("\"d\":"))
        assertTrue(jsonStr.contains("\"rid\":\"X7K2M9P1\""))
    }
    
    @Test
    fun `InnerPacketV2 with empty data`() {
        val inner = InnerPacketV2(
            cmd = "ping",
            d = emptyMap(),
            rid = "ABCD1234"
        )
        
        val jsonStr = json.encodeToString(inner)
        val decoded = json.decodeFromString<InnerPacketV2>(jsonStr)
        
        assertEquals("ping", decoded.cmd)
        assertTrue(decoded.d.isEmpty())
    }
    
    // ============================================================================
    // Blockchain Chain State Tests
    // ============================================================================
    
    @Test
    fun `ChainState initializes to genesis`() {
        val chain = ChainState()
        
        assertEquals(0L, chain.txSeq)
        assertEquals(0L, chain.rxSeq)
        assertEquals(GENESIS_HASH, chain.txHash)
        assertEquals(GENESIS_HASH, chain.rxHash)
        assertTrue(chain.isGenesis())
    }
    
    @Test
    fun `ChainState nextTxSeq returns incremented value`() {
        val chain = ChainState()
        
        assertEquals(1L, chain.nextTxSeq())
        assertEquals(1L, chain.nextTxSeq()) // Still 1 until updateTx
    }
    
    @Test
    fun `ChainState updateTx updates state`() {
        val chain = ChainState()
        val hash = "a".repeat(64)
        
        chain.updateTx(1, hash)
        
        assertEquals(1L, chain.txSeq)
        assertEquals(hash, chain.txHash)
        assertEquals(2L, chain.nextTxSeq())
        assertFalse(chain.isGenesis())
    }
    
    @Test
    fun `ChainState updateRx updates state`() {
        val chain = ChainState()
        val hash = "b".repeat(64)
        
        chain.updateRx(1, hash)
        
        assertEquals(1L, chain.rxSeq)
        assertEquals(hash, chain.rxHash)
        assertEquals(hash, chain.lastReceivedHash)
        assertFalse(chain.isGenesis())
    }
    
    @Test
    fun `ChainState reset returns to genesis`() {
        val chain = ChainState()
        
        chain.updateTx(5, "x".repeat(64))
        chain.updateRx(3, "y".repeat(64))
        
        chain.reset()
        
        assertTrue(chain.isGenesis())
        assertEquals(0L, chain.txSeq)
        assertEquals(0L, chain.rxSeq)
    }
    
    @Test
    fun `ChainState snapshot roundtrip`() {
        val chain = ChainState()
        chain.updateTx(10, "t".repeat(64))
        chain.updateRx(8, "r".repeat(64))
        
        val snapshot = chain.toSnapshot()
        
        val newChain = ChainState()
        newChain.fromSnapshot(snapshot)
        
        assertEquals(10L, newChain.txSeq)
        assertEquals(8L, newChain.rxSeq)
        assertEquals("t".repeat(64), newChain.txHash)
        assertEquals("r".repeat(64), newChain.rxHash)
    }
    
    // ============================================================================
    // Signature Data Format Tests
    // ============================================================================
    
    @Test
    fun `Signature data format v2`() {
        val v = "1.0"
        val id = "WL12345678"
        val seq = 1L
        val prev = GENESIS_HASH
        val p = "payload_hex"
        
        val sigData = "$v|$id|$seq|$prev|$p"
        
        assertEquals("1.0|WL12345678|1|$GENESIS_HASH|payload_hex", sigData)
        assertEquals(5, sigData.split("|").size)
    }
    
    // ============================================================================
    // Integration: Crypto + Packet
    // ============================================================================
    
    @Test
    fun `Create and verify packet signature`() {
        val token = "d".repeat(32)
        val crypto = CryptoPure(token)
        
        val v = "1.0"
        val id = "WL12345678"
        val seq = 1L
        val prev = GENESIS_HASH
        val payload = "encrypted_payload"
        
        val sigData = "$v|$id|$seq|$prev|$payload"
        val signature = crypto.calculateHmac(sigData)
        
        assertTrue(crypto.verifyHmac(sigData, signature))
        
        // Tampered data should fail
        val tamperedSigData = "$v|$id|${seq + 1}|$prev|$payload"
        assertFalse(crypto.verifyHmac(tamperedSigData, signature))
    }
    
    @Test
    fun `Packet hash for blockchain chaining`() {
        val token = "e".repeat(32)
        
        val packet = OuterPacketV2(
            v = "1.0",
            id = "WL12345678",
            seq = 1,
            prev = GENESIS_HASH,
            p = "payload",
            sig = "sig"
        )
        
        val packetJson = json.encodeToString(packet)
        val hash = CryptoPure.sha256(packetJson.toByteArray(Charsets.UTF_8))
        
        assertEquals(32, hash.size)
        assertEquals(64, hash.toHex().length)
    }
    
    // ============================================================================
    // Helper Data Classes (mirror Protocol v1.0 structure)
    // ============================================================================
    
    @Serializable
    data class OuterPacketV2(
        val v: String = "1.0",
        val id: String = "",
        val seq: Long = 0,
        val prev: String = "",
        val p: String = "",
        val sig: String = ""
    )
    
    @Serializable
    data class InnerPacketV2(
        val cmd: String,
        val d: Map<String, String> = emptyMap(),
        val rid: String = ""
    )
    
    class ChainState {
        var txSeq: Long = 0
            private set
        var txHash: String = GENESIS_HASH
            private set
        var rxSeq: Long = 0
            private set
        var rxHash: String = GENESIS_HASH
            private set
        var lastReceivedHash: String = GENESIS_HASH
            private set
        
        fun nextTxSeq(): Long = txSeq + 1
        
        fun updateTx(newSeq: Long, packetHash: String) {
            txSeq = newSeq
            txHash = packetHash
        }
        
        fun updateRx(newSeq: Long, packetHash: String) {
            rxSeq = newSeq
            rxHash = packetHash
            lastReceivedHash = packetHash
        }
        
        fun reset() {
            txSeq = 0
            txHash = GENESIS_HASH
            rxSeq = 0
            rxHash = GENESIS_HASH
            lastReceivedHash = GENESIS_HASH
        }
        
        fun isGenesis(): Boolean = 
            txSeq == 0L && rxSeq == 0L && 
            txHash == GENESIS_HASH && rxHash == GENESIS_HASH
        
        fun toSnapshot() = ChainStateSnapshot(txSeq, txHash, rxSeq, rxHash, lastReceivedHash)
        
        fun fromSnapshot(s: ChainStateSnapshot) {
            txSeq = s.txSeq
            txHash = s.txHash
            rxSeq = s.rxSeq
            rxHash = s.rxHash
            lastReceivedHash = s.lastReceivedHash
        }
    }
    
    @Serializable
    data class ChainStateSnapshot(
        val txSeq: Long = 0,
        val txHash: String = GENESIS_HASH,
        val rxSeq: Long = 0,
        val rxHash: String = GENESIS_HASH,
        val lastReceivedHash: String = GENESIS_HASH
    )
    
    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xFF) }
}
