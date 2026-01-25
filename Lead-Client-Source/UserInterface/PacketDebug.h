#pragma once
/**
 * @file PacketDebug.h
 * @brief Minimal Packet Debug Middleware
 * 
 * Uses auto-generated registrations from PacketDebugRegGen.h
 * Run generate_packet_debug.py after modifying packet.h
 */

#ifndef __PACKET_DEBUG_H__
#define __PACKET_DEBUG_H__

#ifdef _DEBUG

#include <windows.h>
#include <stdio.h>
#include <share.h>
#include <map>
#include <functional>

#define PACKET_DEBUG_LOG_FILE "debug_packet.log"


typedef std::function<void(FILE*, const void*, int)> PacketPrinter;

class CPacketDebug
{
public:
    static CPacketDebug& Instance() { static CPacketDebug inst; return inst; }

    void Initialize()
    {
        if (m_bInit) return;
        m_pFile = _fsopen(PACKET_DEBUG_LOG_FILE, "a", _SH_DENYNO);
        if (!m_pFile) return;
        setvbuf(m_pFile, NULL, _IONBF, 0);
        m_dwLastTime = GetTickCount();
        m_bInit = true;
        m_nRecv = m_nSend = 0;
        
        SYSTEMTIME st; GetLocalTime(&st);
        fprintf(m_pFile, "\n================================================================================\n");
        fprintf(m_pFile, " PACKET DEBUG - %04d-%02d-%02d %02d:%02d:%02d\n",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        fprintf(m_pFile, "================================================================================\n\n");
    }

    void Shutdown()
    {
        if (!m_bInit) return;
        fprintf(m_pFile, "\n================================================================================\n");
        fprintf(m_pFile, " END - SEND: %u, RECV: %u\n", m_nSend, m_nRecv);
        fprintf(m_pFile, "================================================================================\n\n");
        fclose(m_pFile);
        m_pFile = NULL;
        m_bInit = false;
    }

    void LogSend(const void* data, int size) { if (m_bInit) { m_nSend++; Log("SEND", data, size, m_Send); } }
    void LogRecv(const void* data, int size) { if (m_bInit) { m_nRecv++; Log("RECV", data, size, m_Recv); } }

    void RegSend(BYTE h, const char* name, PacketPrinter printer) { m_Send[h] = {name, printer}; }
    void RegRecv(BYTE h, const char* name, PacketPrinter printer) { m_Recv[h] = {name, printer}; }
    
    FILE* GetFile() { return m_pFile; }

private:
    struct PktInfo { const char* name; PacketPrinter printer; };
    std::map<BYTE, PktInfo> m_Send, m_Recv;
    
    CPacketDebug() : m_bInit(false), m_pFile(NULL), m_dwLastTime(0), m_nSend(0), m_nRecv(0) {}
    
    void Log(const char* dir, const void* data, int size, std::map<BYTE, PktInfo>& reg)
    {
        if (!data || size < 1 || !m_pFile) return;
        
        BYTE header = ((BYTE*)data)[0];
        DWORD now = GetTickCount();
        DWORD dt = now - m_dwLastTime;
        m_dwLastTime = now;
        
        SYSTEMTIME st; GetLocalTime(&st);
        auto it = reg.find(header);
        
        if (it != reg.end())
        {
            fprintf(m_pFile, "[%02d:%02d:%02d.%03d] %s %s (%d) %d Bytes dt=%u | ",
                   st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                   dir, it->second.name, (int)header, size, dt);
            if (it->second.printer)
                it->second.printer(m_pFile, data, size);
            else
                fprintf(m_pFile, "(no printer)\n");
        }
        else
        {
            fprintf(m_pFile, "[%02d:%02d:%02d.%03d] %s %d %d Bytes dt=%u | not registered\n",
                   st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                   dir, (int)header, size, dt);
        }
    }

    bool m_bInit;
    FILE* m_pFile;
    DWORD m_dwLastTime;
    DWORD m_nSend, m_nRecv;
};

// Include auto-generated registrations
#include "PacketDebugRegGen.h"

// Macros
#define PACKET_DEBUG_INIT()      do { RegisterAllPacketsGenerated(); CPacketDebug::Instance().Initialize(); } while(0)
#define PACKET_DEBUG_SHUTDOWN()  CPacketDebug::Instance().Shutdown()
#define PACKET_DEBUG_SEND(d, s)  CPacketDebug::Instance().LogSend(d, s)
#define PACKET_DEBUG_RECV(d, s)  CPacketDebug::Instance().LogRecv(d, s)

#else // _DEBUG

#define PACKET_DEBUG_INIT()      ((void)0)
#define PACKET_DEBUG_SHUTDOWN()  ((void)0)
#define PACKET_DEBUG_SEND(d, s)  ((void)0)
#define PACKET_DEBUG_RECV(d, s)  ((void)0)

#endif // _DEBUG
#endif // __PACKET_DEBUG_H__
