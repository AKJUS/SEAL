// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/serialization.h"
#include "seal/util/defines.h"
#include <array>
#include <cstdint>
#include <fstream>
#include <functional>
#include <sstream>
#include <string>
#include <vector>
#include "gtest/gtest.h"

using namespace seal;
using namespace std;

namespace sealtest
{
    namespace
    {
        struct test_struct
        {
            int a;
            int b;
            double c;

            void save_members(ostream &stream)
            {
                stream.write(reinterpret_cast<const char *>(&a), sizeof(int));
                stream.write(reinterpret_cast<const char *>(&b), sizeof(int));
                stream.write(reinterpret_cast<const char *>(&c), sizeof(double));
            }

            void load_members(istream &stream)
            {
                stream.read(reinterpret_cast<char *>(&a), sizeof(int));
                stream.read(reinterpret_cast<char *>(&b), sizeof(int));
                stream.read(reinterpret_cast<char *>(&c), sizeof(double));
            }

            streamoff save_size(compr_mode_type compr_mode) const
            {
                size_t members_size = Serialization::ComprSizeEstimate(sizeof(test_struct), compr_mode);

                return static_cast<streamoff>(sizeof(Serialization::SEALHeader) + members_size);
            }
        };

        // A serializable object whose payload is larger than the internal decompression buffer (256 KB), used to
        // exercise multi-chunk streaming inflation.
        struct large_struct
        {
            std::vector<uint8_t> data;

            void save_members(ostream &stream)
            {
                uint64_t n = static_cast<uint64_t>(data.size());
                stream.write(reinterpret_cast<const char *>(&n), sizeof(uint64_t));
                stream.write(reinterpret_cast<const char *>(data.data()), static_cast<streamsize>(data.size()));
            }

            void load_members(istream &stream)
            {
                uint64_t n = 0;
                stream.read(reinterpret_cast<char *>(&n), sizeof(uint64_t));
                data.resize(static_cast<size_t>(n));
                stream.read(reinterpret_cast<char *>(data.data()), static_cast<streamsize>(n));
            }

            streamoff save_size(compr_mode_type compr_mode) const
            {
                size_t raw = sizeof(uint64_t) + data.size();
                return static_cast<streamoff>(
                    sizeof(Serialization::SEALHeader) + Serialization::ComprSizeEstimate(raw, compr_mode));
            }
        };

        // A serializable object that, on save, writes a small prefix followed by a large filler, but on load reads
        // only the prefix. Modeling a hostile/oversized payload: the loader must not need to inflate the unread filler
        // (the decompression-bomb defense), and must leave the stream positioned at the end of the object.
        struct prefix_struct
        {
            static constexpr size_t prefix_size = 32;
            std::array<uint8_t, prefix_size> prefix{};
            std::vector<uint8_t> filler;

            void save_members(ostream &stream)
            {
                stream.write(reinterpret_cast<const char *>(prefix.data()), static_cast<streamsize>(prefix_size));
                stream.write(reinterpret_cast<const char *>(filler.data()), static_cast<streamsize>(filler.size()));
            }

            void load_members(istream &stream)
            {
                // Intentionally reads only the prefix and never the filler.
                stream.read(reinterpret_cast<char *>(prefix.data()), static_cast<streamsize>(prefix_size));
            }

            streamoff save_size(compr_mode_type compr_mode) const
            {
                size_t raw = prefix_size + filler.size();
                return static_cast<streamoff>(
                    sizeof(Serialization::SEALHeader) + Serialization::ComprSizeEstimate(raw, compr_mode));
            }
        };

        // An object that embeds a nested serialized object (itself saved uncompressed), mirroring how real SEAL
        // objects embed sub-objects such as Modulus. Loading it performs a nested Serialization::Load, which verifies
        // its size via tellg() on the (inflating) stream.
        struct nested_struct
        {
            test_struct inner{};
            int32_t tag = 0;

            void save_members(ostream &stream)
            {
                using namespace std::placeholders;
                Serialization::Save(
                    std::bind(&test_struct::save_members, &inner, _1), inner.save_size(compr_mode_type::none), stream,
                    compr_mode_type::none, false);
                stream.write(reinterpret_cast<const char *>(&tag), sizeof(int32_t));
            }

            void load_members(istream &stream)
            {
                using namespace std::placeholders;
                Serialization::Load(std::bind(&test_struct::load_members, &inner, _1), stream, false);
                stream.read(reinterpret_cast<char *>(&tag), sizeof(int32_t));
            }

            streamoff save_size(compr_mode_type compr_mode) const
            {
                size_t raw = static_cast<size_t>(inner.save_size(compr_mode_type::none)) + sizeof(int32_t);
                return static_cast<streamoff>(
                    sizeof(Serialization::SEALHeader) + Serialization::ComprSizeEstimate(raw, compr_mode));
            }
        };

        // The compression modes available in this build.
        std::vector<compr_mode_type> available_compr_modes()
        {
            std::vector<compr_mode_type> modes;
#ifdef SEAL_USE_ZLIB
            modes.push_back(compr_mode_type::zlib);
#endif
#ifdef SEAL_USE_ZSTD
            modes.push_back(compr_mode_type::zstd);
#endif
            return modes;
        }
    } // namespace

    TEST(SerializationTest, IsValidHeader)
    {
        ASSERT_EQ(sizeof(Serialization::SEALHeader), Serialization::seal_header_size);

        Serialization::SEALHeader header;
        ASSERT_TRUE(Serialization::IsValidHeader(header));

#ifdef SEAL_USE_ZLIB
        header.compr_mode = compr_mode_type::zlib;
        ASSERT_TRUE(Serialization::IsValidHeader(header));
#endif

#ifdef SEAL_USE_ZSTD
        header.compr_mode = compr_mode_type::zstd;
        ASSERT_TRUE(Serialization::IsValidHeader(header));
#endif

        Serialization::SEALHeader invalid_header;
        invalid_header.magic = 0x1212;
        ASSERT_FALSE(Serialization::IsValidHeader(invalid_header));
        invalid_header.magic = Serialization::seal_magic;
        ASSERT_EQ(invalid_header.header_size, Serialization::seal_header_size);
        invalid_header.version_major = 0x02;
        ASSERT_FALSE(Serialization::IsValidHeader(invalid_header));
        invalid_header.version_major = SEAL_VERSION_MAJOR;
        invalid_header.compr_mode = (compr_mode_type)0x03;
        ASSERT_FALSE(Serialization::IsValidHeader(invalid_header));
    }

    TEST(SerializationTest, SEALHeaderSaveLoad)
    {
        {
            // Serialize to stream
            Serialization::SEALHeader header, loaded_header;
            header.compr_mode = Serialization::compr_mode_default;
            header.size = 256;

            stringstream stream;
            Serialization::SaveHeader(header, stream);
            ASSERT_TRUE(Serialization::IsValidHeader(header));
            Serialization::LoadHeader(stream, loaded_header);
            ASSERT_EQ(Serialization::seal_magic, loaded_header.magic);
            ASSERT_EQ(Serialization::seal_header_size, loaded_header.header_size);
            ASSERT_EQ(SEAL_VERSION_MAJOR, loaded_header.version_major);
            ASSERT_EQ(SEAL_VERSION_MINOR, loaded_header.version_minor);
            ASSERT_EQ(Serialization::compr_mode_default, loaded_header.compr_mode);
            ASSERT_EQ(0x00, loaded_header.reserved);
            ASSERT_EQ(256, loaded_header.size);
        }
        {
            // Serialize to buffer
            Serialization::SEALHeader header, loaded_header;
            header.compr_mode = Serialization::compr_mode_default;
            header.size = 256;

            vector<seal_byte> buffer(16);
            Serialization::SaveHeader(header, buffer.data(), buffer.size());
            ASSERT_TRUE(Serialization::IsValidHeader(header));
            Serialization::LoadHeader(buffer.data(), buffer.size(), loaded_header);
            ASSERT_EQ(Serialization::seal_magic, loaded_header.magic);
            ASSERT_EQ(Serialization::seal_header_size, loaded_header.header_size);
            ASSERT_EQ(SEAL_VERSION_MAJOR, loaded_header.version_major);
            ASSERT_EQ(SEAL_VERSION_MINOR, loaded_header.version_minor);
            ASSERT_EQ(Serialization::compr_mode_default, loaded_header.compr_mode);
            ASSERT_EQ(0x00, loaded_header.reserved);
            ASSERT_EQ(256, loaded_header.size);
        }
    }
    /*
        TEST(SerializationTest, SEALHeaderUpgrade)
        {
            legacy_headers::SEALHeader_3_4 header_3_4;
            header_3_4.compr_mode = Serialization::compr_mode_default;
            header_3_4.size = 0xF3F3;

            {
                Serialization::SEALHeader header;
                Serialization::LoadHeader(
                    reinterpret_cast<const seal_byte *>(&header_3_4), sizeof(legacy_headers::SEALHeader_3_4), header);
                ASSERT_TRUE(Serialization::IsValidHeader(header));
                ASSERT_EQ(header_3_4.compr_mode, header.compr_mode);
                ASSERT_EQ(header_3_4.size, header.size);
            }
            {
                Serialization::SEALHeader header;
                Serialization::LoadHeader(
                    reinterpret_cast<const seal_byte *>(&header_3_4), sizeof(legacy_headers::SEALHeader_3_4), header,
                    false);

                // No upgrade requested
                ASSERT_FALSE(Serialization::IsValidHeader(header));
            }
        }
    */
    TEST(SerializationTest, SaveLoadToStream)
    {
        test_struct st{ 3, ~0, 3.14159 }, st2;
        using namespace placeholders;
        stringstream stream;

        auto out_size = Serialization::Save(
            bind(&test_struct::save_members, &st, _1), st.save_size(compr_mode_type::none), stream,
            compr_mode_type::none, false);
        auto in_size = Serialization::Load(bind(&test_struct::load_members, &st2, _1), stream, false);
        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(st.a, st2.a);
        ASSERT_EQ(st.b, st2.b);
        ASSERT_EQ(st.c, st2.c);
#ifdef SEAL_USE_ZSTD
        {
            test_struct st3;
            out_size = Serialization::Save(
                bind(&test_struct::save_members, &st, _1), st.save_size(compr_mode_type::zstd), stream,
                compr_mode_type::zstd, false);
            in_size = Serialization::Load(bind(&test_struct::load_members, &st3, _1), stream, false);
            ASSERT_EQ(out_size, in_size);
            ASSERT_EQ(st.a, st3.a);
            ASSERT_EQ(st.b, st3.b);
            ASSERT_EQ(st.c, st3.c);
        }
#endif
#ifdef SEAL_USE_ZLIB
        {
            test_struct st3;
            out_size = Serialization::Save(
                bind(&test_struct::save_members, &st, _1), st.save_size(compr_mode_type::zlib), stream,
                compr_mode_type::zlib, false);
            in_size = Serialization::Load(bind(&test_struct::load_members, &st3, _1), stream, false);
            ASSERT_EQ(out_size, in_size);
            ASSERT_EQ(st.a, st3.a);
            ASSERT_EQ(st.b, st3.b);
            ASSERT_EQ(st.c, st3.c);
        }
#endif
    }

    TEST(SerializationTest, SaveLoadToBuffer)
    {
        test_struct st{ 3, ~0, 3.14159 }, st2;
        using namespace placeholders;

        constexpr size_t arr_size = 1024;
        seal_byte buffer[arr_size]{};

        stringstream ss;
        auto test_out_size = Serialization::Save(
            bind(&test_struct::save_members, &st, _1), st.save_size(Serialization::compr_mode_default), ss,
            Serialization::compr_mode_default, false);
        auto out_size = Serialization::Save(
            bind(&test_struct::save_members, &st, _1), st.save_size(Serialization::compr_mode_default), buffer,
            arr_size, Serialization::compr_mode_default, false);
        ASSERT_EQ(test_out_size, out_size);
        for (size_t i = static_cast<size_t>(out_size); i < arr_size; i++)
        {
            ASSERT_TRUE(seal_byte{} == buffer[i]);
        }

        auto in_size = Serialization::Load(bind(&test_struct::load_members, &st2, _1), buffer, arr_size, false);
        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(st.a, st2.a);
        ASSERT_EQ(st.b, st2.b);
        ASSERT_EQ(st.c, st2.c);
#ifdef SEAL_USE_ZSTD
        {
            // Reset buffer back to zero
            memset(buffer, 0, arr_size);

            test_struct st3;
            ss.seekp(0);
            test_out_size = Serialization::Save(
                bind(&test_struct::save_members, &st, _1), st.save_size(compr_mode_type::zstd), ss,
                compr_mode_type::zstd, false);
            out_size = Serialization::Save(
                bind(&test_struct::save_members, &st, _1), st.save_size(compr_mode_type::zstd), buffer, arr_size,
                compr_mode_type::zstd, false);
            ASSERT_EQ(test_out_size, out_size);
            for (size_t i = static_cast<size_t>(out_size); i < arr_size; i++)
            {
                ASSERT_EQ(seal_byte{}, buffer[i]);
            }

            in_size = Serialization::Load(bind(&test_struct::load_members, &st3, _1), buffer, arr_size, false);
            ASSERT_EQ(out_size, in_size);
            ASSERT_EQ(st.a, st3.a);
            ASSERT_EQ(st.b, st3.b);
            ASSERT_EQ(st.c, st3.c);
        }
#endif
#ifdef SEAL_USE_ZLIB
        {
            // Reset buffer back to zero
            memset(buffer, 0, arr_size);

            test_struct st3;
            ss.seekp(0);
            test_out_size = Serialization::Save(
                bind(&test_struct::save_members, &st, _1), st.save_size(compr_mode_type::zlib), ss,
                compr_mode_type::zlib, false);
            out_size = Serialization::Save(
                bind(&test_struct::save_members, &st, _1), st.save_size(compr_mode_type::zlib), buffer, arr_size,
                compr_mode_type::zlib, false);
            ASSERT_EQ(test_out_size, out_size);
            for (size_t i = static_cast<size_t>(out_size); i < arr_size; i++)
            {
                ASSERT_EQ(seal_byte{}, buffer[i]);
            }

            in_size = Serialization::Load(bind(&test_struct::load_members, &st3, _1), buffer, arr_size, false);
            ASSERT_EQ(out_size, in_size);
            ASSERT_EQ(st.a, st3.a);
            ASSERT_EQ(st.b, st3.b);
            ASSERT_EQ(st.c, st3.c);
        }
#endif
    }

    // Round-trips a payload larger than the 256 KB internal decompression buffer to exercise multi-chunk streaming
    // inflation under each compression mode.
    TEST(SerializationTest, CompressedLargeRoundTrip)
    {
        using namespace placeholders;

        large_struct st;
        st.data.resize(size_t(1) << 20); // 1 MB
        for (size_t i = 0; i < st.data.size(); i++)
        {
            // A deterministic, high-entropy pattern so the payload does not compress away to a single chunk.
            st.data[i] = static_cast<uint8_t>((i * 2654435761ULL + 1013904223ULL) >> 24);
        }

        std::vector<compr_mode_type> modes = available_compr_modes();
        modes.push_back(compr_mode_type::none);

        for (auto mode : modes)
        {
            stringstream stream;
            auto out_size = Serialization::Save(
                bind(&large_struct::save_members, &st, _1), st.save_size(mode), stream, mode, false);

            large_struct st2;
            auto in_size = Serialization::Load(bind(&large_struct::load_members, &st2, _1), stream, false);

            ASSERT_EQ(out_size, in_size);
            ASSERT_EQ(st.data, st2.data);
        }
    }

    // A loader that consumes only part of the decompressed payload must not require the remainder to be inflated (the
    // decompression-bomb defense) and must leave the stream positioned exactly at the end of the object so that a
    // following concatenated object loads correctly.
    TEST(SerializationTest, CompressedPartialConsumptionAndConcatenation)
    {
        using namespace placeholders;

        for (auto mode : available_compr_modes())
        {
            // Filler large enough to span many decompression buffers; incompressible so the compressed payload also
            // exceeds the buffer, forcing the loader to skip an unread compressed remainder.
            prefix_struct first;
            for (size_t i = 0; i < prefix_struct::prefix_size; i++)
            {
                first.prefix[i] = static_cast<uint8_t>(i + 1);
            }
            first.filler.resize(size_t(2) << 20); // 2 MB
            for (size_t i = 0; i < first.filler.size(); i++)
            {
                first.filler[i] = static_cast<uint8_t>((i * 6364136223846793005ULL) >> 56);
            }

            test_struct second{ 11, ~3, 2.71828 };

            stringstream stream;
            Serialization::Save(
                bind(&prefix_struct::save_members, &first, _1), first.save_size(mode), stream, mode, false);
            Serialization::Save(
                bind(&test_struct::save_members, &second, _1), second.save_size(mode), stream, mode, false);

            // Load the first object: reads only the prefix, skips the rest.
            prefix_struct first_loaded;
            Serialization::Load(bind(&prefix_struct::load_members, &first_loaded, _1), stream, false);
            ASSERT_EQ(first.prefix, first_loaded.prefix);

            // Load the second object: succeeds only if the first load left the stream correctly positioned.
            test_struct second_loaded;
            Serialization::Load(bind(&test_struct::load_members, &second_loaded, _1), stream, false);
            ASSERT_EQ(second.a, second_loaded.a);
            ASSERT_EQ(second.b, second_loaded.b);
            ASSERT_EQ(second.c, second_loaded.c);
        }
    }

    // A highly compressible filler (the classic bomb shape: tiny compressed, huge decompressed) that the loader never
    // fully reads must load successfully without inflating the whole payload.
    TEST(SerializationTest, CompressedBombShapeLoads)
    {
        using namespace placeholders;

        for (auto mode : available_compr_modes())
        {
            prefix_struct first;
            for (size_t i = 0; i < prefix_struct::prefix_size; i++)
            {
                first.prefix[i] = static_cast<uint8_t>(0xA0 + i);
            }
            first.filler.assign(size_t(8) << 20, uint8_t(0)); // 8 MB of zeros -> tiny compressed

            stringstream stream;
            Serialization::Save(
                bind(&prefix_struct::save_members, &first, _1), first.save_size(mode), stream, mode, false);

            prefix_struct first_loaded;
            Serialization::Load(bind(&prefix_struct::load_members, &first_loaded, _1), stream, false);
            ASSERT_EQ(first.prefix, first_loaded.prefix);
        }
    }

    // A corrupted compressed body must be rejected cleanly rather than crashing or hanging.
    TEST(SerializationTest, LoadCorruptCompressedThrows)
    {
        using namespace placeholders;

        large_struct st;
        st.data.resize(size_t(1) << 20); // 1 MB, incompressible-ish
        for (size_t i = 0; i < st.data.size(); i++)
        {
            st.data[i] = static_cast<uint8_t>((i * 2654435761ULL) >> 24);
        }

        for (auto mode : available_compr_modes())
        {
            stringstream stream;
            Serialization::Save(bind(&large_struct::save_members, &st, _1), st.save_size(mode), stream, mode, false);

            string bytes = stream.str();
            // Mangle the compressed body (leave the header intact and the length unchanged).
            for (size_t i = sizeof(Serialization::SEALHeader) + 16; i < bytes.size(); i += 11)
            {
                bytes[i] = static_cast<char>(bytes[i] ^ 0xFF);
            }

            stringstream corrupt(bytes);
            large_struct st2;
            ASSERT_ANY_THROW(Serialization::Load(bind(&large_struct::load_members, &st2, _1), corrupt, false));
        }
    }

    // Regression test for nested loads through the inflating buffer: an object whose load performs a nested
    // Serialization::Load (which verifies its size via tellg()) must round-trip, including interleaved save/load on a
    // single stream as real objects do.
    TEST(SerializationTest, CompressedNestedAndInterleaved)
    {
        using namespace placeholders;

        std::vector<compr_mode_type> modes = available_compr_modes();
        modes.push_back(compr_mode_type::none);

        for (auto mode : modes)
        {
            nested_struct first;
            first.inner = test_struct{ 5, 6, 7.5 };
            first.tag = 1234;

            stringstream stream;
            Serialization::Save(
                bind(&nested_struct::save_members, &first, _1), first.save_size(mode), stream, mode, false);

            nested_struct first_loaded;
            Serialization::Load(bind(&nested_struct::load_members, &first_loaded, _1), stream, false);
            ASSERT_EQ(first.inner.a, first_loaded.inner.a);
            ASSERT_EQ(first.inner.b, first_loaded.inner.b);
            ASSERT_EQ(first.inner.c, first_loaded.inner.c);
            ASSERT_EQ(first.tag, first_loaded.tag);

            // Save and load a second object on the same stream (interleaved), which only works if the first load left
            // the stream correctly positioned and in a good state.
            nested_struct second;
            second.inner = test_struct{ -1, 9, 0.25 };
            second.tag = 4321;
            Serialization::Save(
                bind(&nested_struct::save_members, &second, _1), second.save_size(mode), stream, mode, false);

            nested_struct second_loaded;
            Serialization::Load(bind(&nested_struct::load_members, &second_loaded, _1), stream, false);
            ASSERT_EQ(second.inner.a, second_loaded.inner.a);
            ASSERT_EQ(second.inner.b, second_loaded.inner.b);
            ASSERT_EQ(second.inner.c, second_loaded.inner.c);
            ASSERT_EQ(second.tag, second_loaded.tag);
        }
    }

    // A truncated compressed stream must be rejected cleanly.
    TEST(SerializationTest, LoadTruncatedCompressedThrows)
    {
        using namespace placeholders;

        large_struct st;
        st.data.resize(size_t(1) << 20); // 1 MB
        for (size_t i = 0; i < st.data.size(); i++)
        {
            st.data[i] = static_cast<uint8_t>((i * 40503ULL) >> 8);
        }

        for (auto mode : available_compr_modes())
        {
            stringstream stream;
            Serialization::Save(bind(&large_struct::save_members, &st, _1), st.save_size(mode), stream, mode, false);

            string bytes = stream.str();
            ASSERT_GT(bytes.size(), sizeof(Serialization::SEALHeader) + 64);
            bytes.resize(bytes.size() / 2); // drop the second half of the compressed payload

            stringstream truncated(bytes);
            large_struct st2;
            ASSERT_ANY_THROW(Serialization::Load(bind(&large_struct::load_members, &st2, _1), truncated, false));
        }
    }
} // namespace sealtest
