#pragma once
/**
 * @file PacketDebug.h
 * @brief Minimal Packet Debug Middleware
 * 
 * Lightweight packet logger for debugging network traffic.
 * Only active in DEBUG builds - zero overhead in Release.
 * Writes to debug_log.txt in the game folder.
 * 
 * Usage:
 *   PKT_DEBUG_INIT()           - Call once at startup
 *   PKT_DEBUG_SEND(data, size) - Log outgoing packet
 *   PKT_DEBUG_RECV(data, size) - Log incoming packet
 *   PKT_DEBUG_SHUTDOWN()       - Call on exit
 */

#ifndef __PACKET_DEBUG_H__
#define __PACKET_DEBUG_H__

// Enable packet debug in all builds (comment out to disable)
#define ENABLE_PACKET_DEBUG

#ifdef ENABLE_PACKET_DEBUG

#include <windows.h>
#include <stdio.h>
#include <share.h>
#include <string>

// CONFIGURATION
#define PKT_DBG_MIN_STR_LEN     3       // Min chars to detect as string
#define PKT_DBG_MAX_FIELDS      16      // Max fields to display per packet
#define PKT_DBG_LOG_FILE        "debug_packet.log"

class CPacketDebug
{
public:
    static CPacketDebug& Instance() { static CPacketDebug inst; return inst; }

    void Initialize()
    {
        if (m_bInit) return;
        
        // Save log file in same directory as exe
        strcpy(m_szLogPath, PKT_DBG_LOG_FILE);
        
        // Open log file with sharing, append mode
        m_pFile = _fsopen(m_szLogPath, "a", _SH_DENYNO);
        if (!m_pFile) return;
        
        // Disable buffering for immediate writes
        setvbuf(m_pFile, NULL, _IONBF, 0);
        
        m_dwLastTime = GetTickCount();
        m_bInit = true;
        
        // Write session header
        SYSTEMTIME st; GetLocalTime(&st);
        fprintf(m_pFile, "\n");
        fprintf(m_pFile, "==========================================================================================\n");
        fprintf(m_pFile, "  PACKET DEBUG SESSION - %04d-%02d-%02d %02d:%02d:%02d\n",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        fprintf(m_pFile, "  Log file: %s\n", m_szLogPath);
        fprintf(m_pFile, "==========================================================================================\n");
        fprintf(m_pFile, " DIR  |     TIME      | DT(ms) |   HEADER ID   | SIZE  | CONTENT\n");
        fprintf(m_pFile, "------+---------------+--------+---------------+-------+----------------------------------\n");
    }

    void Shutdown()
    {
        if (!m_bInit) return;
        
        fprintf(m_pFile, "==========================================================================================\n");
        fprintf(m_pFile, " SESSION END - SEND: %u packets | RECV: %u packets\n", m_nSend, m_nRecv);
        fprintf(m_pFile, "==========================================================================================\n\n");
        
        fclose(m_pFile);
        m_pFile = NULL;
        m_bInit = false;
    }

    void LogSend(const void* data, int size) { if (m_bInit) { m_nSend++; Log("SEND", data, size); } }
    void LogRecv(const void* data, int size) { if (m_bInit) { m_nRecv++; Log("RECV", data, size); } }

private:
    CPacketDebug() : m_bInit(false), m_pFile(NULL), m_dwLastTime(0), m_nSend(0), m_nRecv(0) { m_szLogPath[0] = 0; }
    
    void Log(const char* dir, const void* data, int size)
    {
        if (!data || size < 1 || !m_pFile) return;
        
        const BYTE* p = (const BYTE*)data;
        BYTE header = p[0];
        
        // Time
        DWORD now = GetTickCount();
        DWORD dt = now - m_dwLastTime;
        m_dwLastTime = now;
        
        SYSTEMTIME st; GetLocalTime(&st);
        
        // Print header line with packet counter
        fprintf(m_pFile, " %s #%u | %02d:%02d:%02d.%03d | %6u | %3u (0x%02X)    | %5d |",
               dir, m_nSend + m_nRecv, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
               dt, header, header, size);
        
        // Parse and print content
        PrintContent(p, size);
    }
    
    void PrintContent(const BYTE* data, int size)
    {
        if (size <= 1) { fprintf(m_pFile, " (empty)\n"); return; }
        
        int pos = 1;  // Skip header byte
        
        // Check for dynamic packet (header + WORD size)
        if (size >= 3 && *(WORD*)(data + 1) == size) { pos = 3; }
        if (pos >= size) { fprintf(m_pFile, " (header only)\n"); return; }
        
        fprintf(m_pFile, "\n");
        int fieldCount = 0;
        
        while (pos < size && fieldCount < PKT_DBG_MAX_FIELDS)
        {
            // Try to detect string first (null-terminated printable chars)
            if (IsPrintable(data[pos]))
            {
                int strStart = pos;
                std::string s;
                while (pos < size && data[pos] != 0 && IsPrintable(data[pos]) && s.length() < 64)
                    s += (char)data[pos++];
                
                if (s.length() >= PKT_DBG_MIN_STR_LEN && (pos >= size || data[pos] == 0))
                {
                    fprintf(m_pFile, "       [%03d] char[%zu]: \"%s\"\n", strStart, s.length() + 1, s.c_str());
                    if (pos < size && data[pos] == 0) pos++;
                    fieldCount++;
                    continue;
                }
                pos = strStart;
            }
            
            // Try to detect fixed-size char array (padded with nulls)
            int fixedStrLen = DetectFixedString(data + pos, size - pos);
            if (fixedStrLen > 0)
            {
                std::string s;
                for (int i = 0; i < fixedStrLen && data[pos + i] != 0; i++)
                    s += (char)data[pos + i];
                fprintf(m_pFile, "       [%03d] char[%d]: \"%s\"\n", pos, fixedStrLen, s.c_str());
                pos += fixedStrLen;
                fieldCount++;
                continue;
            }
            
            // Try float
            if (pos + 4 <= size)
            {
                float fval = *(float*)(data + pos);
                if (IsReasonableFloat(fval))
                {
                    fprintf(m_pFile, "       [%03d] float: %.4f\n", pos, fval);
                    pos += 4;
                    fieldCount++;
                    continue;
                }
            }
            
            // Try 32-bit types (DWORD/long/int)
            if (pos + 4 <= size)
            {
                DWORD uval = *(DWORD*)(data + pos);
                long sval = *(long*)(data + pos);
                
                // Check if it's a signed negative value
                if (sval < 0 && sval > -100000000)
                {
                    fprintf(m_pFile, "       [%03d] long: %ld (0x%08X)\n", pos, sval, uval);
                    pos += 4;
                    fieldCount++;
                    continue;
                }
                else if (IsReasonableDWORD(uval))
                {
                    fprintf(m_pFile, "       [%03d] DWORD: %u (0x%08X)\n", pos, uval, uval);
                    pos += 4;
                    fieldCount++;
                    continue;
                }
            }
            
            // Try 16-bit types (WORD/short)
            if (pos + 2 <= size)
            {
                WORD uval = *(WORD*)(data + pos);
                short sval = *(short*)(data + pos);
                
                // Check if it's a signed negative value
                if (sval < 0 && sval > -32000)
                {
                    fprintf(m_pFile, "       [%03d] short: %d (0x%04X)\n", pos, sval, uval);
                    pos += 2;
                    fieldCount++;
                    continue;
                }
                else if (uval > 0 && uval < 0xFFF0)
                {
                    fprintf(m_pFile, "       [%03d] WORD: %u (0x%04X)\n", pos, uval, uval);
                    pos += 2;
                    fieldCount++;
                    continue;
                }
            }
            
            // Single BYTE/BOOL
            BYTE val = data[pos];
            if (val == 0 || val == 1)
                fprintf(m_pFile, "       [%03d] BYTE/bool: %u\n", pos, val);
            else
                fprintf(m_pFile, "       [%03d] BYTE: %u (0x%02X)\n", pos, val, val);
            pos++;
            fieldCount++;
        }
        
        if (pos < size)
            fprintf(m_pFile, "       ... +%d more bytes\n", size - pos);
    }
    
    int DetectFixedString(const BYTE* data, int maxLen)
    {
        // All common sizes from packet.h:
        // 13, 16, 17 (PASSWD+1), 24, 25 (NAME+1), 31 (LOGIN+1), 32, 33 (filename+1), 
        // 48, 64, 65 (msg+1), 128, 256 (szBuf+1)
        static const int sizes[] = {13, 16, 17, 24, 25, 31, 32, 33, 48, 64, 65, 128, 256};
        for (int sz : sizes)
        {
            if (sz > maxLen) break;
            int printable = 0, nulls = 0;
            bool valid = true;
            for (int i = 0; i < sz && valid; i++)
            {
                if (IsPrintable(data[i])) printable++;
                else if (data[i] == 0) nulls++;
                else valid = false;
            }
            if (valid && printable >= PKT_DBG_MIN_STR_LEN && nulls > 0 && printable + nulls == sz)
                return sz;
        }
        return 0;
    }
    
    bool IsPrintable(BYTE c) { return c >= 32 && c < 127; }
    
    bool IsReasonableFloat(float val)
    {
        if (val != val) return false;
        if (val > 1e10f || val < -1e10f) return false;
        if (val == 0.0f) return false;
        // Reasonable range for game values (angles, volumes, coordinates)
        float absVal = val < 0 ? -val : val;
        return (absVal >= 0.0001f && absVal <= 100000.0f);
    }
    
    bool IsReasonableDWORD(DWORD val)
    {
        if (val == 0 || val == 0xFFFFFFFF) return false;
        if (val > 0xF0000000) return false;
        return true;
    }

    bool m_bInit;
    FILE* m_pFile;
    DWORD m_dwLastTime;
    DWORD m_nSend, m_nRecv;
    char m_szLogPath[MAX_PATH];
};

// MACROS
#define PKT_DEBUG_INIT()          CPacketDebug::Instance().Initialize()
#define PKT_DEBUG_SHUTDOWN()      CPacketDebug::Instance().Shutdown()
#define PKT_DEBUG_SEND(d, s)      CPacketDebug::Instance().LogSend(d, s)
#define PKT_DEBUG_RECV(d, s)      CPacketDebug::Instance().LogRecv(d, s)

#else // ENABLE_PACKET_DEBUG not defined

#define PKT_DEBUG_INIT()          ((void)0)
#define PKT_DEBUG_SHUTDOWN()      ((void)0)
#define PKT_DEBUG_SEND(d, s)      ((void)0)
#define PKT_DEBUG_RECV(d, s)      ((void)0)

#endif // ENABLE_PACKET_DEBUG
#endif
