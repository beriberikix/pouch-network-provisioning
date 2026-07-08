// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

package io.golioth.pouchprov.cbor

import java.io.ByteArrayOutputStream

/**
 * Minimal definite-length CBOR (RFC 8949) writer/reader for the fixed
 * provisioning message set and the pouch header.
 *
 * Deliberately tiny and dependency-free. It mirrors the byte output of Python's
 * `cbor2.dumps` **defaults** — which this project's golden vectors were produced
 * with — so it is *not* canonical CBOR: map keys are emitted in insertion order
 * (never sorted), while integers and lengths always use the minimal-length form.
 *
 * Supported value model (encode & decode):
 *  - integers   -> [Long] (signed; major types 0 and 1)
 *  - byte str   -> [ByteArray] (major type 2)
 *  - text str   -> [String] (major type 3)
 *  - array      -> [List] (major type 4)
 *  - map        -> [LinkedHashMap] preserving order (major type 5)
 *  - bool/null  -> [Boolean] / null (major type 7)
 */
object Cbor {

    class DecodeException(message: String) : Exception(message)

    // ---- encode ----------------------------------------------------------

    fun encode(value: Any?): ByteArray {
        val out = ByteArrayOutputStream()
        write(out, value)
        return out.toByteArray()
    }

    private fun write(out: ByteArrayOutputStream, value: Any?) {
        when (value) {
            null -> out.write(0xF6)
            is Boolean -> out.write(if (value) 0xF5 else 0xF4)
            is Int -> writeInt(out, value.toLong())
            is Long -> writeInt(out, value)
            is ByteArray -> {
                writeHead(out, 2, value.size.toLong())
                out.write(value)
            }
            is String -> {
                val bytes = value.toByteArray(Charsets.UTF_8)
                writeHead(out, 3, bytes.size.toLong())
                out.write(bytes)
            }
            is List<*> -> {
                writeHead(out, 4, value.size.toLong())
                for (item in value) write(out, item)
            }
            is Map<*, *> -> {
                writeHead(out, 5, value.size.toLong())
                for ((k, v) in value) {
                    write(out, k)
                    write(out, v)
                }
            }
            else -> throw IllegalArgumentException("cannot CBOR-encode ${value::class}")
        }
    }

    private fun writeInt(out: ByteArrayOutputStream, value: Long) {
        if (value >= 0) {
            writeHead(out, 0, value)
        } else {
            writeHead(out, 1, -1 - value)
        }
    }

    /** Write the major type and its (unsigned) argument in minimal-length form. */
    private fun writeHead(out: ByteArrayOutputStream, major: Int, arg: Long) {
        val m = major shl 5
        when {
            arg < 24L -> out.write(m or arg.toInt())
            arg <= 0xFFL -> {
                out.write(m or 24)
                out.write(arg.toInt())
            }
            arg <= 0xFFFFL -> {
                out.write(m or 25)
                out.write((arg ushr 8).toInt() and 0xFF)
                out.write(arg.toInt() and 0xFF)
            }
            arg <= 0xFFFFFFFFL -> {
                out.write(m or 26)
                for (shift in intArrayOf(24, 16, 8, 0)) out.write((arg ushr shift).toInt() and 0xFF)
            }
            else -> {
                out.write(m or 27)
                for (shift in intArrayOf(56, 48, 40, 32, 24, 16, 8, 0)) {
                    out.write((arg ushr shift).toInt() and 0xFF)
                }
            }
        }
    }

    // ---- decode ----------------------------------------------------------

    /** Decode a single CBOR item from the start of [data]. Extra trailing bytes are ignored. */
    fun decode(data: ByteArray): Any? = Reader(data).read()

    /** Decode a single item and also return how many bytes it consumed. */
    fun decodeWithLength(data: ByteArray): Pair<Any?, Int> {
        val r = Reader(data)
        val v = r.read()
        return v to r.pos
    }

    private class Reader(val data: ByteArray) {
        var pos = 0

        fun read(): Any? {
            val initial = u8()
            val major = initial ushr 5
            val ai = initial and 0x1F
            return when (major) {
                0 -> argument(ai)
                1 -> -1L - argument(ai)
                2 -> bytes(argument(ai).toInt())
                3 -> String(bytes(argument(ai).toInt()), Charsets.UTF_8)
                4 -> {
                    val n = argument(ai).toInt()
                    val list = ArrayList<Any?>(n)
                    repeat(n) { list.add(read()) }
                    list
                }
                5 -> {
                    val n = argument(ai).toInt()
                    val map = LinkedHashMap<Any?, Any?>(n * 2)
                    repeat(n) {
                        val k = read()
                        val v = read()
                        map[k] = v
                    }
                    map
                }
                7 -> when (ai) {
                    20 -> false
                    21 -> true
                    22 -> null
                    else -> throw DecodeException("unsupported simple value $ai")
                }
                else -> throw DecodeException("unsupported major type $major")
            }
        }

        private fun argument(ai: Int): Long = when {
            ai < 24 -> ai.toLong()
            ai == 24 -> u8().toLong()
            ai == 25 -> readBE(2)
            ai == 26 -> readBE(4)
            ai == 27 -> readBE(8)
            else -> throw DecodeException("bad additional info $ai")
        }

        private fun readBE(n: Int): Long {
            var v = 0L
            repeat(n) { v = (v shl 8) or u8().toLong() }
            return v
        }

        private fun u8(): Int {
            if (pos >= data.size) throw DecodeException("truncated CBOR")
            return data[pos++].toInt() and 0xFF
        }

        private fun bytes(n: Int): ByteArray {
            if (n < 0 || pos + n > data.size) throw DecodeException("truncated CBOR string")
            val b = data.copyOfRange(pos, pos + n)
            pos += n
            return b
        }
    }
}
