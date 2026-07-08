// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

package io.golioth.pouchprov.pouch

import io.golioth.pouchprov.cbor.Cbor
import java.io.ByteArrayOutputStream

/**
 * Pouch wire framing: header, blocks and entries.
 *
 * Formats mirror the pouch reference implementation (github.com/golioth/pouch:
 * src/header.cddl, src/block.c, src/entry.c) and the Python `pouchlink.pouch`.
 *
 * Block:
 *   0..1  size (be16, excluding the size field itself, including the id byte)
 *   2     id byte: low 5 bits stream id (0 = entry block), 0x40 = first, 0x80 = last
 *   3..   payload
 *
 * Entry (within an entry block):
 *   0..1  data_len (be16)
 *   2..3  content_type (be16, IANA CoAP content format)
 *   4     path_len
 *   5..   path, then data
 */
object Pouch {
    const val POUCH_VERSION = 1

    const val CONTENT_TYPE_OCTET_STREAM = 42
    const val CONTENT_TYPE_JSON = 50
    const val CONTENT_TYPE_CBOR = 60

    const val BLOCK_ID_ENTRY = 0x00
    const val BLOCK_ID_MASK = 0x1F
    const val BLOCK_FIRST = 0x40
    const val BLOCK_LAST = 0x80
    const val BLOCK_HEADER_SIZE = 3

    const val ENTRY_HEADER_OVERHEAD = 5

    const val ENCRYPTION_NONE = 0
    const val ENCRYPTION_SAEAD = 1

    const val ROLE_DEVICE = 0
    const val ROLE_SERVER = 1

    const val ALG_CHACHA20_POLY1305 = 1
    const val ALG_AES_GCM = 2

    const val DEFAULT_BLOCK_SIZE = 512

    class DecodeException(message: String) : Exception(message)

    /**
     * Build a plaintext (encryption-none) pouch carrying [entries].
     *
     * Entries are packed into entry blocks of at most [blockSize] payload bytes;
     * an entry never spans blocks (pouch src/entry.c contract).
     */
    fun buildEntryPouch(deviceId: String, entries: List<Entry>, blockSize: Int = DEFAULT_BLOCK_SIZE): ByteArray {
        val blocks = ArrayList<Block>()
        var current = ByteArrayOutputStream()
        for (entry in entries) {
            val encoded = entry.encode()
            if (encoded.size > blockSize) {
                throw IllegalArgumentException("entry for ${entry.path} exceeds block size $blockSize")
            }
            if (current.size() > 0 && current.size() + encoded.size > blockSize) {
                blocks.add(Block(current.toByteArray(), first = blocks.isEmpty(), last = false))
                current = ByteArrayOutputStream()
            }
            current.write(encoded)
        }
        blocks.add(Block(current.toByteArray(), first = blocks.isEmpty(), last = true))

        val out = ByteArrayOutputStream()
        out.write(PouchHeader.plaintext(deviceId).encode())
        for (block in blocks) out.write(block.encode())
        return out.toByteArray()
    }

    /** Parse entries out of concatenated entry-block payloads. */
    fun parseEntryBlocks(payloads: List<ByteArray>): List<Entry> {
        val data = concat(payloads)
        val entries = ArrayList<Entry>()
        var pos = 0
        while (pos < data.size) {
            if (data.size - pos < ENTRY_HEADER_OVERHEAD) throw DecodeException("truncated entry header")
            val dataLen = be16(data, pos)
            val contentType = be16(data, pos + 2)
            val pathLen = data[pos + 4].toInt() and 0xFF
            pos += ENTRY_HEADER_OVERHEAD
            if (data.size - pos < pathLen + dataLen) throw DecodeException("truncated entry")
            val path = String(data, pos, pathLen, Charsets.UTF_8)
            pos += pathLen
            val payload = data.copyOfRange(pos, pos + dataLen)
            pos += dataLen
            entries.add(Entry(path, contentType, payload))
        }
        return entries
    }

    /**
     * Parse a plaintext pouch into its header and entries. saead pouches must
     * have their blocks decrypted first (out of scope for the plaintext path).
     */
    fun parsePouch(data: ByteArray): Pair<PouchHeader, List<Entry>> {
        val (header, consumed) = PouchHeader.decode(data)
        val rawBlocks = splitBlocks(data.copyOfRange(consumed, data.size))
        if (header.encryption != ENCRYPTION_NONE) throw DecodeException("encrypted pouch passed to parsePouch")
        val payloads = rawBlocks.filter { it.streamId == BLOCK_ID_ENTRY }.map { it.payload }
        return header to parseEntryBlocks(payloads)
    }

    data class RawBlock(val streamId: Int, val first: Boolean, val last: Boolean, val payload: ByteArray)

    /** Split the block section into raw blocks. */
    fun splitBlocks(data: ByteArray): List<RawBlock> {
        val blocks = ArrayList<RawBlock>()
        var pos = 0
        while (pos < data.size) {
            if (data.size - pos < BLOCK_HEADER_SIZE) throw DecodeException("truncated block header")
            val size = be16(data, pos)
            val idByte = data[pos + 2].toInt() and 0xFF
            val payloadLen = size - 1 // size includes the id byte
            pos += BLOCK_HEADER_SIZE
            if (payloadLen < 0 || data.size - pos < payloadLen) throw DecodeException("truncated block payload")
            blocks.add(
                RawBlock(
                    idByte and BLOCK_ID_MASK,
                    idByte and BLOCK_FIRST != 0,
                    idByte and BLOCK_LAST != 0,
                    data.copyOfRange(pos, pos + payloadLen),
                ),
            )
            pos += payloadLen
        }
        return blocks
    }

    private fun be16(data: ByteArray, off: Int): Int =
        ((data[off].toInt() and 0xFF) shl 8) or (data[off + 1].toInt() and 0xFF)

    private fun concat(chunks: List<ByteArray>): ByteArray {
        val out = ByteArrayOutputStream()
        for (c in chunks) out.write(c)
        return out.toByteArray()
    }
}

/** A single pouch entry: a message on a reserved `.prov/` path. */
data class Entry(val path: String, val contentType: Int, val data: ByteArray) {
    fun encode(): ByteArray {
        val pathBytes = path.toByteArray(Charsets.UTF_8)
        require(pathBytes.size <= 255) { "path too long" }
        val out = ByteArrayOutputStream()
        out.write((data.size ushr 8) and 0xFF)
        out.write(data.size and 0xFF)
        out.write((contentType ushr 8) and 0xFF)
        out.write(contentType and 0xFF)
        out.write(pathBytes.size and 0xFF)
        out.write(pathBytes)
        out.write(data)
        return out.toByteArray()
    }

    override fun equals(other: Any?): Boolean =
        other is Entry && path == other.path && contentType == other.contentType && data.contentEquals(other.data)

    override fun hashCode(): Int = (path.hashCode() * 31 + contentType) * 31 + data.contentHashCode()
}

/** A pouch block: an id byte plus a payload. */
data class Block(
    val payload: ByteArray,
    val streamId: Int = Pouch.BLOCK_ID_ENTRY,
    val first: Boolean = true,
    val last: Boolean = true,
) {
    fun encode(): ByteArray {
        var idByte = streamId and Pouch.BLOCK_ID_MASK
        if (first) idByte = idByte or Pouch.BLOCK_FIRST
        if (last) idByte = idByte or Pouch.BLOCK_LAST
        // size excludes the 2-byte size field but includes the id byte
        val size = payload.size + 1
        val out = ByteArrayOutputStream()
        out.write((size ushr 8) and 0xFF)
        out.write(size and 0xFF)
        out.write(idByte)
        out.write(payload)
        return out.toByteArray()
    }

    override fun equals(other: Any?): Boolean =
        other is Block && streamId == other.streamId && first == other.first &&
            last == other.last && payload.contentEquals(other.payload)

    override fun hashCode(): Int =
        ((payload.contentHashCode() * 31 + streamId) * 31 + first.hashCode()) * 31 + last.hashCode()
}

/**
 * Pouch header per src/header.cddl.
 *
 * Plaintext: `[1, [0, device_id]]`
 * saead:     `[1, [1, session_info, pouch_id]]` (decoded for detection; the
 *            encrypted payload path is a follow-up — see the plan's crypto seam).
 */
data class PouchHeader(
    val encryption: Int = Pouch.ENCRYPTION_NONE,
    val deviceId: String? = null,
    val sessionInfo: List<Any?>? = null,
    val pouchId: Long = 0,
) {
    fun encode(): ByteArray {
        val info: List<Any?> = if (encryption == Pouch.ENCRYPTION_NONE) {
            requireNotNull(deviceId) { "plaintext header requires device_id" }
            listOf(Pouch.ENCRYPTION_NONE.toLong(), deviceId)
        } else {
            requireNotNull(sessionInfo) { "saead header requires session info" }
            listOf(Pouch.ENCRYPTION_SAEAD.toLong(), sessionInfo, pouchId)
        }
        return Cbor.encode(listOf(Pouch.POUCH_VERSION.toLong(), info))
    }

    companion object {
        fun plaintext(deviceId: String) = PouchHeader(Pouch.ENCRYPTION_NONE, deviceId = deviceId)

        /** Decode a header from the start of [data]; returns it and bytes consumed. */
        fun decode(data: ByteArray): Pair<PouchHeader, Int> {
            val (obj, consumed) = try {
                Cbor.decodeWithLength(data)
            } catch (e: Exception) {
                throw Pouch.DecodeException("bad pouch header: ${e.message}")
            }
            if (obj !is List<*> || obj.size != 2) throw Pouch.DecodeException("pouch header is not a 2-element array")
            val version = (obj[0] as? Long)?.toInt()
            if (version != Pouch.POUCH_VERSION) throw Pouch.DecodeException("unsupported pouch version $version")
            val info = obj[1] as? List<*> ?: throw Pouch.DecodeException("bad encryption info")
            if (info.isEmpty()) throw Pouch.DecodeException("bad encryption info")
            return when ((info[0] as? Long)?.toInt()) {
                Pouch.ENCRYPTION_NONE -> PouchHeader(Pouch.ENCRYPTION_NONE, deviceId = info[1] as String?) to consumed
                Pouch.ENCRYPTION_SAEAD -> PouchHeader(
                    Pouch.ENCRYPTION_SAEAD,
                    sessionInfo = @Suppress("UNCHECKED_CAST") (info[1] as List<Any?>),
                    pouchId = (info[2] as? Long) ?: 0L,
                ) to consumed
                else -> throw Pouch.DecodeException("unknown encryption type ${info[0]}")
            }
        }
    }
}
