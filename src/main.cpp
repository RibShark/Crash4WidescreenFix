#define _USE_MATH_DEFINES
#include <cmath>
#include <Trampoline.h>
#include "MemoryMgr.h"
#include "Patterns.h"

namespace WidescreenFix
{
    static float hFov;

    static void CalculateNew_hFov() {
        // Calculation taken from https://www.purebasic.fr/english/viewtopic.php?t=37014
        hFov = atan (tan ((hFov * M_PI) / 360.0) * (64.0/27.0)/1.777778)*360.0 / M_PI;
    }
}

void OnInitializeHook() {
    using namespace Memory;
    using namespace hook::txn;

    std::unique_ptr<ScopedUnprotect::Unprotect> Protect = ScopedUnprotect::UnprotectSectionOrFullModule( GetModuleHandle( nullptr ), ".text" );

    try {
        using namespace WidescreenFix;
        auto ptn = pattern ("F3 0F 11 47 18 8B 83 00 02 00 00"); // 0x141E6C84F

        // First, disable bConstrainAspectRatio
        // TODO: Re-enable this during FMV cutscenes
        Patch<uint8_t>(ptn.get_first(26), 0);

        Trampoline* trampoline = Trampoline::MakeTrampoline( ptn.get_first() );
        auto calculateTrampoline = trampoline->Jump(CalculateNew_hFov);

        auto jmpAddr = ptn.get_first(5);

        const uint8_t shellcode[] = {
                0xF3, 0x0F, 0x11, 0x47, 0x18, // movss, [rdi+18h], xmm0 - original instruction
                0x8B, 0x47, 0x18, // mov eax, [rdi+18h]
                0xA3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs [hFov], eax
                0xE8, 0x00, 0x00, 0x00, 0x00, // call ds:[CalculateNew_hFov]
                0xA1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs eax, [hFov]
                0x89, 0x47, 0x18, // mov [rdi+18h], eax
                0xE9, 0x00, 0x00, 0x00, 0x00 // jmp jmpAddr
        };

        std::byte* space = trampoline->RawSpace( sizeof(shellcode) );
        memcpy_s( space, sizeof(shellcode), shellcode, sizeof(shellcode) );

        // Fill pointers
        Patch( space + 5 + 3 + 1, &hFov );
        WriteOffsetValue( space + 5 + 3 + 9 + 1, calculateTrampoline );
        Patch( space + 5 + 3 + 9 + 5 + 1, &hFov );
        WriteOffsetValue( space + 5 + 3 + 9 + 5 + 9 + 3 + 1, jmpAddr);

        InjectHook( ptn.get_first(), space, PATCH_JUMP );
    }
    TXN_CATCH();
}