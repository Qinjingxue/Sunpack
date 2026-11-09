#include <ui_core.h>
#include <ui/renderer.h>
#include <ui/display_list.h>
#include <ui/render_thread.h>
#include <ui/ui_context.h>
#include <ui/ui_window.h>
#include "background.hpp"
#include <cassert>
#include <cstring>
#include <iostream>
#include <stdexcept>

namespace {
bool transparent(HWND hwnd) {
    BYTE alpha=255; DWORD flags=0;
    return GetLayeredWindowAttributes(hwnd,nullptr,&alpha,&flags) &&
        (flags&LWA_ALPHA) && alpha==0;
}
MSG startup_completion(HWND hwnd, WPARAM afterToken=0) {
    const auto deadline=GetTickCount64()+5000;
    for(;;) {
        MSG message{};
        while(PeekMessageW(&message,hwnd,0,0,PM_REMOVE)) {
            if(message.message==ui::kUiCoreStartupPresentedMessage && message.wParam>afterToken) return message;
            TranslateMessage(&message); DispatchMessageW(&message);
        }
        const auto now=GetTickCount64();
        if(now>=deadline) throw std::runtime_error("No presented startup frame");
        MsgWaitForMultipleObjectsEx(0,nullptr,DWORD(deadline-now),QS_ALLINPUT,MWMO_INPUTAVAILABLE);
    }
}
void startup_present_contracts() {
    // Final screenshots cannot detect revealing an unpresented buffer. Hold the
    // real render completion in the UI queue and inspect HWND alpha before/after
    // dispatch, including a stale completion from an interrupted show attempt.
    assert(ui_init()==0);
    UiWindowConfig config{};
    config.title=L"SunPack startup check";
    config.width=240; config.height=180; config.tool_window=1;
    config.skip_animation=1;
    auto handle=ui_window_create(&config); assert(handle);
    auto* window=ui::GetContext().GetWindow(handle); assert(window);
    auto hwnd=window->Handle();
    window->SetRoot(std::make_shared<ui::Widget>());
    window->ShowImmediate(false);
    assert(IsWindowVisible(hwnd) && transparent(hwnd));
    window->ShowImmediate(false); // An explicit retry stays behind the same gate.
    assert(transparent(hwnd));
    auto stale=startup_completion(hwnd);
    assert(transparent(hwnd));
    window->Hide();
    DispatchMessageW(&stale);
    assert(!IsWindowVisible(hwnd) && transparent(hwnd));
    window->ShowImmediate(false);
    auto presented=startup_completion(hwnd,stale.wParam);
    assert(presented.wParam!=stale.wParam && transparent(hwnd));
    DispatchMessageW(&stale);
    assert(transparent(hwnd));
    DispatchMessageW(&presented);
    assert(IsWindowVisible(hwnd) && !(GetWindowLongPtrW(hwnd,GWL_EXSTYLE)&WS_EX_LAYERED));
    window->ShowImmediate(false); // Already shown must not become transparent.
    assert(!(GetWindowLongPtrW(hwnd,GWL_EXSTYLE)&WS_EX_LAYERED));

    // The clear must follow the live page, while translucent/absent page
    // backgrounds and explicitly transparent windows keep their old behavior.
    {
        auto root=window->Root();
        gui_test::clear_color(*window,theme::kWindowBg());
        root->bgColor=D2D1::ColorF(0x202020);
        gui_test::clear_color(*window,root->bgColor);
        D2D1_COLOR_F live=D2D1::ColorF(0x2b2b2b);
        root->bgColorFn=[&] { return live; };
        gui_test::clear_color(*window,live);
        live=theme::Current().elevatedBg;
        gui_test::clear_color(*window,live);
        live.a=0.5f;
        gui_test::clear_color(*window,theme::kWindowBg());
        root->bgColorFn=nullptr;
        window->SetBackgroundMode(1);
        gui_test::clear_color(*window,{0,0,0,0});
        window->SetBackgroundMode(0);
        root->bgColor={0,0,0,0};
    }

    window->Hide();
    window->Show();
    presented=startup_completion(hwnd,presented.wParam);
    assert(transparent(hwnd)); // Open-animation timer cannot reveal early.
    DispatchMessageW(&presented);
    window->Hide(); // Cancel the animation and its already posted timer message.
    window->ShowImmediate(false);
    presented=startup_completion(hwnd,presented.wParam);
    assert(transparent(hwnd));
    DispatchMessageW(&presented);
    assert(!(GetWindowLongPtrW(hwnd,GWL_EXSTYLE)&WS_EX_LAYERED));

    window->Hide();
    window->startMaximizedPending_=true;
    window->PrepareRT();
    window->ShowImmediate(false);
    assert(IsZoomed(hwnd) && transparent(hwnd));
    presented=startup_completion(hwnd,presented.wParam);
    DispatchMessageW(&presented);
    assert(IsZoomed(hwnd) && !(GetWindowLongPtrW(hwnd,GWL_EXSTYLE)&WS_EX_LAYERED));

    window->Hide();
    window->SetWindowAlpha(0);
    window->ShowImmediate(false);
    window->SetWindowAlpha(128); // Same operation used by popup DrawTree.
    assert(transparent(hwnd));
    presented=startup_completion(hwnd,presented.wParam);
    DispatchMessageW(&presented);
    BYTE alpha=0; DWORD flags=0;
    assert(GetLayeredWindowAttributes(hwnd,nullptr,&alpha,&flags) && alpha==128);
    window->SetWindowAlpha(255);
    assert(GetLayeredWindowAttributes(hwnd,nullptr,&alpha,&flags) && alpha==255);

    window->Hide();
    window->ShowImmediate(false);
    presented=startup_completion(hwnd,presented.wParam);
    bool closed=false,reported=false;
    window->onRenderFailure=[&] { reported=true; };
    window->onClose=[&] { closed=true; };
    auto failed=presented;
    failed.message=ui::kUiCoreStartupFailedMessage;
    DispatchMessageW(&failed); // Deterministic fatal-result handler injection.
    assert(reported && closed && !IsWindow(hwnd));

    handle=ui_window_create(&config); assert(handle);
    window=ui::GetContext().GetWindow(handle); hwnd=window->Handle();
    window->SetRoot(std::make_shared<ui::Widget>());
    window->ShowImmediate(false);
    presented.hwnd=hwnd; // Simulate reuse of the old HWND by a new window.
    DispatchMessageW(&presented);
    assert(transparent(hwnd));
    // Close while the render thread owns the first frame. Destruction must not
    // wait for reveal, resurrect the HWND, or leak its render registration.
    ui_window_destroy(handle);
    assert(!IsWindow(hwnd) && ui::RenderThread::Instance().RegisteredWindowCount()==0);
    ui_shutdown();
    MSG quit{};
    while(PeekMessageW(&quit,nullptr,WM_QUIT,WM_QUIT,PM_REMOVE)) {}
}

struct Surface {
    HWND hwnd=nullptr;
    ui::Renderer renderer;
    explicit Surface(int x) {
        hwnd=CreateWindowExW(WS_EX_TOOLWINDOW|WS_EX_NOACTIVATE,L"STATIC",L"SunPack rendering check",
            WS_POPUP,x,20,640,480,nullptr,nullptr,GetModuleHandleW(nullptr),nullptr);
        assert(hwnd && renderer.Init() && renderer.CreateRenderTarget(hwnd));
        ShowWindow(hwnd,SW_SHOWNOACTIVATE);
    }
    ~Surface() { renderer.ReleaseRenderTarget(); DestroyWindow(hwnd); }
};
std::vector<unsigned char> pixels(ui::Renderer& renderer) {
    auto* context=renderer.RT();
    ComPtr<ID2D1Image> image; context->GetTarget(&image);
    ComPtr<ID2D1Bitmap1> target; assert(SUCCEEDED(image.As(&target)));
    const auto size=target->GetPixelSize();
    D2D1_BITMAP_PROPERTIES1 props=D2D1::BitmapProperties1(
        D2D1_BITMAP_OPTIONS_CPU_READ|D2D1_BITMAP_OPTIONS_CANNOT_DRAW,
        D2D1::PixelFormat(DXGI_FORMAT_B8G8R8A8_UNORM,D2D1_ALPHA_MODE_PREMULTIPLIED));
    ComPtr<ID2D1Bitmap1> copy; assert(SUCCEEDED(context->CreateBitmap(size,nullptr,0,&props,&copy)));
    assert(SUCCEEDED(copy->CopyFromBitmap(nullptr,target.Get(),nullptr)));
    D2D1_MAPPED_RECT mapped{}; assert(SUCCEEDED(copy->Map(D2D1_MAP_OPTIONS_READ,&mapped)));
    std::vector<unsigned char> result(size.width*size.height*4);
    for(UINT y=0;y<size.height;++y) std::memcpy(result.data()+size_t(y)*size.width*4,mapped.bits+size_t(y)*mapped.pitch,size.width*4);
    copy->Unmap(); return result;
}
ui::DisplayList scene(Surface& surface,int step) {
    if(step==17) step=16;
    ui::DisplayList base;
    RECT rc{}; GetClientRect(surface.hwnd,&rc);
    base.width_px=rc.right; base.height_px=rc.bottom;
    base.dpi_scale=float(GetDpiForWindow(surface.hwnd))/96;
    base.default_font=surface.renderer.DefaultFontFamily();
    if(auto* font=surface.renderer.LatinFontFamily()) base.latin_font=font;
    if(auto* font=surface.renderer.CjkFontFamily()) base.cjk_font=font;
    base.text_render_mode=int(surface.renderer.TextRenderMode());
    ui::DisplayListRecorder r(std::move(base));
    r.Clear(D2D1::ColorF(step>=14?0x202020:0xf3f3f3));
    if (step>=21) {
        // Isolated ink changes must erase old overhangs without repainting an
        // unrelated rounded layer. Alignment, wrap and live transforms all
        // contribute to the true DirectWrite paint origin.
        r.FillRect({0,0,420,320},D2D1::ColorF(0xfafafa));
        ui::TextStyle style; style.font_family=L"Segoe UI"; style.font_size=19;
        style.alignment=step%3; style.paragraph_alignment=(step/2)%3;
        style.word_wrap=step%2!=0;
        r.PushClip({9,9,410,310});
        r.PushTransform(D2D1::Matrix3x2F::Scale(1.0f,1.05f)*
            D2D1::Matrix3x2F::Rotation(3)*D2D1::Matrix3x2F::Translation(0.125f*(step%3),0.375f));
        r.DrawText(step%2?L"中文 e\u0301 😀 fff italic-overhang":L"更新 / shorter",{18,24,275,122},style);
        r.PopTransform();
        r.PushRoundedClip({40,180,360,280},12,12);
        r.FillRect({30,170,370,290},D2D1::ColorF(0x90a0b0));
        r.DrawText(L"unchanged clipped text",{50,185,350,270},style);
        r.PopRoundedClip();
        r.PopClip();
        return r.Finish();
    }
    r.FillRect({0,0,96,320},D2D1::ColorF(0xdddddd));
    ui::TextStyle text; text.font_family=L"Segoe UI"; text.font_size=14;
    r.DrawText(L"导航 / Navigation",{3,5,94,55},text);
    ui::SvgDocumentRef icon;
    icon.viewport_w=icon.viewport_h=24;
    icon.steps.push_back({"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\"><path d=\"M2 2L20 12L2 22Z\" fill=\"#267dcc\"/></svg>"});
    r.DrawSvgDocument(icon,D2D1::Matrix3x2F::Translation(12,70));
    r.PushClip({104,16,400,280});
    const bool entrance=step>=6 && step<13;
    if(entrance) {
        r.PushOpacity(float(step-5)/8,{104,16,400,280});
        r.PushTransform(D2D1::Matrix3x2F::Translation(0,12.75f-float(step-6)*1.375f));
    }
    for(int row=0;row<5;++row) {
        const float y=24+row*52.0f-(entrance?0:float(step%6)*6.125f);
        r.FillRoundedRect({110,y,390,y+46},8,8,D2D1::ColorF(!entrance && row==2 && step%2?0x80a0c0:0xfafafa));
        if(row!=1 || step!=3) {
            auto style=text; style.word_wrap=row==3; style.font_size=step==15?17:14;
            r.DrawText(row==3?L"中文换行 / wrapped text 😀 e\u0301":row==0 && step==8?L"外部更新 changed.001":L"文件名 archive.001",{118,y+3,step==15?260.0f:376.0f,y+40},style);
        }
        r.DrawSvgDocument(icon,D2D1::Matrix3x2F::Translation(360,y+8));
    }
    // Stable commands during entrance; enough distinct colors to exercise the
    // bounded brush cache and scratch brush without changing their appearance.
    for(int n=0;n<180;++n) r.FillRect({110.0f+n,276,111.0f+n,278},D2D1::ColorF(float(n)/181,0.2f,0.4f));
    if(entrance) { r.PopTransform(); r.PopOpacity(); }
    r.PopClip();
    if(step==16 || step==17) r.DrawText(std::wstring(5000,L'字'),{110,285,390,315},text);
    return r.Finish();
}
}

// One end-to-end pixel oracle: optimized partial frames versus fresh full
// replay, including alternating buffers, fractional motion, alpha and lifecycle.
void rendering_contracts() {
    startup_present_contracts();
    // Hidden and prepared buffers must not masquerade as actual presentation.
    // This also exercises the hidden-HWND Present guard on the real driver.
    auto hidden=CreateWindowExW(WS_EX_TOOLWINDOW|WS_EX_LAYERED,L"STATIC",L"Prepared frame check",
        WS_POPUP,20,20,120,80,nullptr,nullptr,GetModuleHandleW(nullptr),nullptr);
    assert(hidden && SetLayeredWindowAttributes(hidden,0,0,LWA_ALPHA));
    {
        ui::RenderWindow target({1,1},hidden);
        auto frame=[&](bool defer) {
            ui::FrameJob job; job.window={1,1}; job.hwnd=hidden;
            job.width_px=120; job.height_px=80; job.defer_present=defer;
            ui::DisplayListRecorder list;
            list.Clear(D2D1::ColorF(0x202020)); job.display_list=list.Finish();
            return job;
        };
        auto skipped=frame(false);
        assert(target.RenderFrame(skipped)==ui::RenderFrameResult::Skipped);
        assert(target.PresentPrepared(true)==ui::RenderFrameResult::Skipped);
        ShowWindow(hidden,SW_SHOWNOACTIVATE);
        auto prepared=frame(true);
        assert(target.RenderFrame(prepared)==ui::RenderFrameResult::Prepared);
        assert(target.PresentPrepared(true)==ui::RenderFrameResult::Presented);
    }
    {
        auto& thread=ui::RenderThread::Instance();
        const ui::RenderWindowId id{12345,1};
        thread.Start(); thread.RegisterWindow(id,hidden);
        ui::FrameJob job; job.window=id; job.hwnd=hidden; job.generation=1;
        job.width_px=120; job.height_px=80; job.defer_present=true;
        job.render_thread_present=true; job.startup_reveal=123;
        ui::DisplayListRecorder list; list.Clear(D2D1::ColorF(0x202020));
        job.display_list=list.Finish(); thread.Submit(std::move(job));
        assert(thread.WaitForGeneration(id.window_id,1,5000));
        MSG message{};
        assert(!PeekMessageW(&message,hidden,ui::kUiCoreStartupPresentedMessage,
            ui::kUiCoreStartupPresentedMessage,PM_REMOVE));
        assert(thread.PresentPrepared(id,true,5000,123));
        assert(PeekMessageW(&message,hidden,ui::kUiCoreStartupPresentedMessage,
            ui::kUiCoreStartupPresentedMessage,PM_REMOVE) && message.wParam==123);
        thread.UnregisterWindow(id); thread.Stop();
    }
    DestroyWindow(hidden);
    Surface actual(20),reference(700);
    // Existing frame-damage scenes have no find ranges. Check shaped UTF-16
    // ranges, both colors, clipped active hits, and record/replay in one scene.
    {
        auto& r=actual.renderer;
        ui::DisplayList base; base.width_px=640; base.height_px=480;
        ui::DisplayListRecorder recorder(std::move(base));
        r.BeginDraw();
        r.SetDisplayListRecorder(&recorder);
        std::vector<ui::TextHighlight> ranges{{3,2,true},{6,2,false}};
        r.textHighlights=&ranges;
        r.DrawText(L"😀 中匹配 匹配",{20,20,290,65},D2D1::ColorF(0xffffff),20);
        ranges={{60,4,true}};
        r.DrawText(std::wstring(60,L'字')+L"匹配文字",{20,80,180,115},D2D1::ColorF(0xffffff),14,
            DWRITE_TEXT_ALIGNMENT_LEADING,DWRITE_FONT_WEIGHT_NORMAL,DWRITE_PARAGRAPH_ALIGNMENT_CENTER,false,nullptr,true);
        r.textHighlights=nullptr;
        r.SetDisplayListRecorder(nullptr);
        auto list=recorder.Finish();
        r.skipPresent=true; assert(SUCCEEDED(r.EndDraw()));
        size_t orange=0,yellow=0;
        for(auto& command:list.commands) if(command.type==ui::DrawCommandType::FillRoundedRect) {
            if(std::abs(command.color.r-245.0f/255)<0.001f) ++orange;
            if(std::abs(command.color.r-247.0f/255)<0.001f) ++yellow;
        }
        assert(orange>=2 && yellow>=1);
        r.BeginDraw(); r.ReplayDisplayList(list); r.skipPresent=true; assert(SUCCEEDED(r.EndDraw()));
    }
    for(int step=0;step<31;++step) {
        if(step==18) {
            for(auto* surface:{&actual,&reference}) {
                SetWindowPos(surface->hwnd,nullptr,0,0,720,500,SWP_NOMOVE|SWP_NOZORDER|SWP_NOACTIVATE);
                surface->renderer.Resize(720,500);
            }
        }
        if(step==19) for(auto* surface:{&actual,&reference}) {
            surface->renderer.ReleaseRenderTarget();
            assert(surface->renderer.CreateRenderTarget(surface->hwnd));
        }
        if(step==20) for(auto* surface:{&actual,&reference}) {
            surface->renderer.SetCjkFonts(L"Arial",L"Microsoft YaHei UI");
            surface->renderer.SetTextRenderMode(theme::TextRenderMode::ClearType);
        }
        auto optimized=scene(actual,step),full=scene(reference,step);
        actual.renderer.PrepareDisplayList(optimized);
        actual.renderer.BeginDraw();
        actual.renderer.RenderDisplayList(std::move(optimized),true);
        actual.renderer.skipPresent=true;
        assert(SUCCEEDED(actual.renderer.EndDraw()));
        // Invalidate only reference caches, leaving its pixels and buffer order.
        reference.renderer.SetDefaultFontFamily(L"Segoe UI");
        reference.renderer.BeginDraw(); reference.renderer.ReplayDisplayList(full);
        reference.renderer.skipPresent=true;
        assert(SUCCEEDED(reference.renderer.EndDraw()));
        const auto a=pixels(actual.renderer),b=pixels(reference.renderer);
        assert(a.size()==b.size());
        size_t differing=0; int largest=0;
        for(size_t i=0;i<a.size();++i) {
            int delta=std::abs(int(a[i])-int(b[i]));
            if(delta>1) ++differing;
            largest=std::max(largest,delta);
        }
        if(differing) throw std::runtime_error("Rendering differs at step "+std::to_string(step)+
            ": channels="+std::to_string(differing)+" max="+std::to_string(largest));
        assert(SUCCEEDED(actual.renderer.PresentPrepared(true)));
        assert(SUCCEEDED(reference.renderer.PresentPrepared(true)));
    }
}
