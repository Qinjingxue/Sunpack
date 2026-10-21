#include "display_list.h"

#include "resource_store.h"

#include <algorithm>
#include <utility>
#include <cstring>
#include <cmath>

namespace ui {

namespace {
bool SameRect(D2D1_RECT_F a, D2D1_RECT_F b) {
    return a.left == b.left && a.top == b.top && a.right == b.right && a.bottom == b.bottom;
}
bool SameColor(D2D1_COLOR_F a, D2D1_COLOR_F b) {
    return a.r == b.r && a.g == b.g && a.b == b.b && a.a == b.a;
}
bool SameMatrix(const D2D1_MATRIX_3X2_F& a, const D2D1_MATRIX_3X2_F& b) {
    return std::memcmp(&a, &b, sizeof(a)) == 0;
}
bool EmptyRect(D2D1_RECT_F r) { return r.right <= r.left || r.bottom <= r.top; }
D2D1_RECT_F UnionRect(D2D1_RECT_F a, D2D1_RECT_F b) {
    if (EmptyRect(a)) return b;
    if (EmptyRect(b)) return a;
    return {std::min(a.left,b.left),std::min(a.top,b.top),std::max(a.right,b.right),std::max(a.bottom,b.bottom)};
}
D2D1_RECT_F IntersectRect(D2D1_RECT_F a, D2D1_RECT_F b) {
    return {std::max(a.left,b.left),std::max(a.top,b.top),std::min(a.right,b.right),std::min(a.bottom,b.bottom)};
}
D2D1_RECT_F TransformRect(D2D1_RECT_F r, const D2D1_MATRIX_3X2_F& m) {
    auto point=[&](float x,float y){ return D2D1_POINT_2F{x*m._11+y*m._21+m._31,x*m._12+y*m._22+m._32}; };
    const auto a=point(r.left,r.top),b=point(r.right,r.top),c=point(r.left,r.bottom),d=point(r.right,r.bottom);
    return {std::min({a.x,b.x,c.x,d.x}),std::min({a.y,b.y,c.y,d.y}),
            std::max({a.x,b.x,c.x,d.x}),std::max({a.y,b.y,c.y,d.y})};
}
}

bool EqualSvgDocument(const SvgDocumentRef& s, const SvgDocumentRef& t) {
    if(s.viewport_w!=t.viewport_w || s.viewport_h!=t.viewport_h || s.steps.size()!=t.steps.size()) return false;
    for(size_t i=0;i<s.steps.size();++i) {
        const auto& u=s.steps[i]; const auto& v=t.steps[i];
        if(u.xml!=v.xml || u.shadow_xml!=v.shadow_xml || u.dx!=v.dx || u.dy!=v.dy || u.std_deviation!=v.std_deviation) return false;
    }
    return true;
}

bool EqualDrawCommand(const DisplayList& a, size_t ai, const DisplayList& b, size_t bi) {
    if (ai >= a.commands.size() || bi >= b.commands.size()) return false;
    const auto& x=a.commands[ai]; const auto& y=b.commands[bi];
    if (x.type!=y.type || !SameRect(x.rect,y.rect) || !SameColor(x.color,y.color) ||
        x.p0.x!=y.p0.x || x.p0.y!=y.p0.y || x.p1.x!=y.p1.x || x.p1.y!=y.p1.y ||
        x.stroke_width!=y.stroke_width || x.radius_x!=y.radius_x || x.radius_y!=y.radius_y ||
        x.blur_radius!=y.blur_radius || x.opacity!=y.opacity || x.sampling!=y.sampling || !SameMatrix(x.transform,y.transform)) return false;
    switch (x.type) {
    case DrawCommandType::DrawText: {
        const auto& s=x.text_style; const auto& t=y.text_style;
        return x.text_index<a.text_pool.size() && y.text_index<b.text_pool.size() &&
            a.text_pool[x.text_index]==b.text_pool[y.text_index] && SameColor(s.color,t.color) &&
            s.font_size==t.font_size && s.font_family==t.font_family && s.alignment==t.alignment &&
            s.paragraph_alignment==t.paragraph_alignment && s.weight==t.weight && s.word_wrap==t.word_wrap;
    }
    case DrawCommandType::DrawImage:
    case DrawCommandType::FillImagePattern:
        return x.image_ref_index<a.image_refs.size() && y.image_ref_index<b.image_refs.size() &&
               a.image_refs[x.image_ref_index].key==b.image_refs[y.image_ref_index].key;
    case DrawCommandType::DrawSvgIcon: {
        if (x.svg_ref_index>=a.svg_icon_refs.size() || y.svg_ref_index>=b.svg_icon_refs.size()) return false;
        const auto& s=a.svg_icon_refs[x.svg_ref_index]; const auto& t=b.svg_icon_refs[y.svg_ref_index];
        if (s.view_box_w!=t.view_box_w || s.view_box_h!=t.view_box_h || s.path_data!=t.path_data || s.layers.size()!=t.layers.size()) return false;
        for (size_t i=0;i<s.layers.size();++i) {
            const auto& u=s.layers[i]; const auto& v=t.layers[i];
            if (u.path_data!=v.path_data || u.opacity!=v.opacity || u.stroke_width!=v.stroke_width || !SameMatrix(u.transform,v.transform)) return false;
        }
        return true;
    }
    case DrawCommandType::FillQuad:
        return x.quad_index<a.quad_refs.size() && y.quad_index<b.quad_refs.size() &&
            std::memcmp(a.quad_refs[x.quad_index].pts,b.quad_refs[y.quad_index].pts,sizeof(QuadRef::pts))==0;
    case DrawCommandType::FillGradient: {
        if (x.gradient_ref_index>=a.gradient_refs.size() || y.gradient_ref_index>=b.gradient_refs.size()) return false;
        const auto& s=a.gradient_refs[x.gradient_ref_index]; const auto& t=b.gradient_refs[y.gradient_ref_index];
        if (s.radial!=t.radial || s.angle_deg!=t.angle_deg || s.cx_pct!=t.cx_pct || s.cy_pct!=t.cy_pct ||
            s.radius_pct!=t.radius_pct || s.tile_w!=t.tile_w || s.tile_h!=t.tile_h || s.pos_x!=t.pos_x || s.pos_y!=t.pos_y || s.stops.size()!=t.stops.size()) return false;
        for(size_t i=0;i<s.stops.size();++i) if(s.stops[i].position!=t.stops[i].position || !SameColor(s.stops[i].color,t.stops[i].color)) return false;
        return true;
    }
    case DrawCommandType::DrawSvgDocument: {
        if(x.svg_document_ref_index>=a.svg_document_refs.size() || y.svg_document_ref_index>=b.svg_document_refs.size()) return false;
        return EqualSvgDocument(a.svg_document_refs[x.svg_document_ref_index],b.svg_document_refs[y.svg_document_ref_index]);
    }
    // Backdrop sampling depends on pixels outside its output rectangle.
    case DrawCommandType::DrawSvgTextRuns:
    case DrawCommandType::DrawBackdropBlur:
        return false;
    default: return true;
    }
}

DisplayListBounds AnalyzeDisplayList(const DisplayList& list, DisplayListInkQuery inkQuery, void* inkContext) {
    DisplayListBounds result;
    result.commands.resize(list.commands.size());
    result.ends.assign(list.commands.size(),size_t(-1));
    const float scale=list.dpi_scale>0?list.dpi_scale:1;
    const D2D1_RECT_F window{0,0,list.width_px/scale,list.height_px/scale};
    auto matrix=D2D1::Matrix3x2F::Identity();
    std::vector<D2D1_MATRIX_3X2_F> transforms;
    std::vector<D2D1_RECT_F> clips{window};
    struct Group { size_t index; DrawCommandType pop; };
    std::vector<Group> groups;
    for(size_t i=0;i<list.commands.size();++i) {
        const auto& c=list.commands[i];
        switch(c.type) {
        case DrawCommandType::PushTransform:
            transforms.push_back(matrix); matrix=D2D1::Matrix3x2F(c.transform._11,c.transform._12,c.transform._21,c.transform._22,c.transform._31,c.transform._32)*matrix;
            groups.push_back({i,DrawCommandType::PopTransform}); continue;
        case DrawCommandType::PushClip:
        case DrawCommandType::PushClipAliased:
        case DrawCommandType::PushRoundedClip:
        case DrawCommandType::PushOpacity:
            clips.push_back(IntersectRect(clips.back(),TransformRect(c.rect,matrix)));
            groups.push_back({i,c.type==DrawCommandType::PushOpacity?DrawCommandType::PopOpacity:
                c.type==DrawCommandType::PushRoundedClip?DrawCommandType::PopRoundedClip:DrawCommandType::PopClip});
            continue;
        case DrawCommandType::PopTransform:
        case DrawCommandType::PopClip:
        case DrawCommandType::PopRoundedClip:
        case DrawCommandType::PopOpacity:
            if(groups.empty() || groups.back().pop!=c.type) { result.incremental=false; continue; }
            result.ends[groups.back().index]=i;
            result.commands[i]=result.commands[groups.back().index]; groups.pop_back();
            if(c.type==DrawCommandType::PopTransform) {
                if(transforms.empty()) { result.incremental=false; continue; }
                matrix=D2D1::Matrix3x2F(transforms.back()._11,transforms.back()._12,transforms.back()._21,transforms.back()._22,transforms.back()._31,transforms.back()._32); transforms.pop_back();
            } else if(clips.size()>1) clips.pop_back(); else result.incremental=false;
            continue;
        default: break;
        }
        D2D1_RECT_F bounds{};
        if(c.type==DrawCommandType::Clear) bounds=clips.back();
        else if(c.type==DrawCommandType::DrawText || c.type==DrawCommandType::DrawSvgIcon || c.type==DrawCommandType::DrawSvgDocument) {
            D2D1_RECT_F ink{};
            if (inkQuery && inkQuery(list, i, ink, inkContext)) {
                // Allow grid fitting and anti-aliasing beyond the DIP ink box.
                const float pad=2/scale;
                ink=TransformRect(ink,matrix);
                ink={ink.left-pad,ink.top-pad,ink.right+pad,ink.bottom+pad};
                bounds=IntersectRect(clips.back(),ink);
            } else bounds=clips.back();
        } else if(c.type==DrawCommandType::DrawSvgTextRuns || c.type==DrawCommandType::DrawBackdropBlur) {
            result.incremental=false; bounds=window;
        } else {
            auto local=c.rect;
            if(c.type==DrawCommandType::DrawLine) local={std::min(c.p0.x,c.p1.x),std::min(c.p0.y,c.p1.y),std::max(c.p0.x,c.p1.x),std::max(c.p0.y,c.p1.y)};
            if(c.type==DrawCommandType::FillQuad && c.quad_index<list.quad_refs.size()) {
                const auto& p=list.quad_refs[c.quad_index].pts;
                local={std::min({p[0].x,p[1].x,p[2].x,p[3].x}),std::min({p[0].y,p[1].y,p[2].y,p[3].y}),
                       std::max({p[0].x,p[1].x,p[2].x,p[3].x}),std::max({p[0].y,p[1].y,p[2].y,p[3].y})};
            }
            const float margin=std::max(0.0f,c.stroke_width)+3*std::max(0.0f,c.blur_radius)+2/scale;
            local={local.left-margin,local.top-margin,local.right+margin,local.bottom+margin};
            bounds=IntersectRect(clips.back(),TransformRect(local,matrix));
        }
        result.commands[i]=bounds;
        for(auto group:groups) result.commands[group.index]=UnionRect(result.commands[group.index],bounds);
    }
    if(!groups.empty() || !transforms.empty() || clips.size()!=1) result.incremental=false;
    return result;
}

D2D1_RECT_F DisplayListDamage(const DisplayList& previous, const DisplayListBounds& oldBounds,
    const DisplayList& next, const DisplayListBounds& newBounds) {
    const float scale=next.dpi_scale>0?next.dpi_scale:1;
    const D2D1_RECT_F full{0,0,next.width_px/scale,next.height_px/scale};
    if(previous.Empty() || previous.width_px!=next.width_px || previous.height_px!=next.height_px ||
       previous.dpi_scale!=next.dpi_scale || !oldBounds.incremental || !newBounds.incremental) return full;
    D2D1_RECT_F damage{};
    size_t first=0,oldEnd=previous.commands.size(),newEnd=next.commands.size();
    while(first<std::min(oldEnd,newEnd) && EqualDrawCommand(previous,first,next,first)) ++first;
    while(oldEnd>first && newEnd>first && EqualDrawCommand(previous,oldEnd-1,next,newEnd-1)) { --oldEnd; --newEnd; }
    for(size_t i=first;i<oldEnd;++i) if(i>=newEnd || !EqualDrawCommand(previous,i,next,i)) damage=UnionRect(damage,oldBounds.commands[i]);
    for(size_t i=first;i<newEnd;++i) if(i>=oldEnd || !EqualDrawCommand(previous,i,next,i)) damage=UnionRect(damage,newBounds.commands[i]);
    return IntersectRect(damage,full);
}

DisplayList::~DisplayList() {
    ReleaseOwnedResources();
}

DisplayList::DisplayList(DisplayList&& other) noexcept
    : window_id(other.window_id),
      generation(other.generation),
      width_px(other.width_px),
      height_px(other.height_px),
      dpi_scale(other.dpi_scale),
      default_font(std::move(other.default_font)),
      latin_font(std::move(other.latin_font)),
      cjk_font(std::move(other.cjk_font)),
      text_render_mode(other.text_render_mode),
      commands(std::move(other.commands)),
      text_pool(std::move(other.text_pool)),
      image_refs(std::move(other.image_refs)),
      gradient_refs(std::move(other.gradient_refs)),
      svg_icon_refs(std::move(other.svg_icon_refs)),
      svg_document_refs(std::move(other.svg_document_refs)),
      svg_text_refs(std::move(other.svg_text_refs)),
      quad_refs(std::move(other.quad_refs)),
      owned_resources_(std::move(other.owned_resources_)) {
    other.owned_resources_.clear();
}

DisplayList& DisplayList::operator=(DisplayList&& other) noexcept {
    if (this == &other) return *this;
    ReleaseOwnedResources();
    window_id = other.window_id;
    generation = other.generation;
    width_px = other.width_px;
    height_px = other.height_px;
    dpi_scale = other.dpi_scale;
    default_font=std::move(other.default_font);
    latin_font=std::move(other.latin_font);
    cjk_font=std::move(other.cjk_font);
    text_render_mode=other.text_render_mode;
    commands = std::move(other.commands);
    text_pool = std::move(other.text_pool);
    image_refs = std::move(other.image_refs);
    gradient_refs = std::move(other.gradient_refs);
    svg_icon_refs = std::move(other.svg_icon_refs);
    svg_document_refs = std::move(other.svg_document_refs);
    svg_text_refs = std::move(other.svg_text_refs);
    quad_refs = std::move(other.quad_refs);
    owned_resources_ = std::move(other.owned_resources_);
    other.owned_resources_.clear();
    return *this;
}

void DisplayList::Clear() {
    commands.clear();
    text_pool.clear();
    image_refs.clear();
    gradient_refs.clear();
    svg_icon_refs.clear();
    svg_document_refs.clear();
    svg_text_refs.clear();
    quad_refs.clear();
    ReleaseOwnedResources();
}

void DisplayList::AddOwnedResource(ResourceKey key) {
    if (!key.IsValid()) return;
    const auto it = std::find(owned_resources_.begin(), owned_resources_.end(), key);
    if (it != owned_resources_.end()) return;
    owned_resources_.push_back(key);
}

void DisplayList::ReleaseOwnedResources() {
    for (const auto& key : owned_resources_) {
        GlobalResourceStore().Remove(key);
    }
    owned_resources_.clear();
}

DisplayListRecorder::DisplayListRecorder(DisplayList base)
    : list_(std::move(base)) {}

void DisplayListRecorder::Reset(DisplayList base) {
    list_ = std::move(base);
}

void DisplayListRecorder::Clear(D2D1_COLOR_F color) {
    auto& cmd = AddCommand(DrawCommandType::Clear);
    cmd.color = color;
}

void DisplayListRecorder::PushClip(D2D1_RECT_F rect) {
    auto& cmd = AddCommand(DrawCommandType::PushClip);
    cmd.rect = rect;
}

void DisplayListRecorder::PushClipAliased(D2D1_RECT_F rect) {
    auto& cmd = AddCommand(DrawCommandType::PushClipAliased);
    cmd.rect = rect;
}

void DisplayListRecorder::PopClip() {
    AddCommand(DrawCommandType::PopClip);
}

void DisplayListRecorder::PushRoundedClip(D2D1_RECT_F rect, float rx, float ry) {
    auto& cmd = AddCommand(DrawCommandType::PushRoundedClip);
    cmd.rect = rect;
    cmd.radius_x = rx;
    cmd.radius_y = ry;
}

void DisplayListRecorder::PopRoundedClip() {
    AddCommand(DrawCommandType::PopRoundedClip);
}

void DisplayListRecorder::PushOpacity(float opacity, D2D1_RECT_F bounds) {
    auto& cmd = AddCommand(DrawCommandType::PushOpacity);
    cmd.rect = bounds;
    cmd.opacity = opacity;
}

void DisplayListRecorder::PopOpacity() {
    AddCommand(DrawCommandType::PopOpacity);
}

void DisplayListRecorder::PushTransform(D2D1_MATRIX_3X2_F transform) {
    auto& cmd = AddCommand(DrawCommandType::PushTransform);
    cmd.transform = transform;
}

void DisplayListRecorder::PopTransform() {
    AddCommand(DrawCommandType::PopTransform);
}

void DisplayListRecorder::FillRect(D2D1_RECT_F rect, D2D1_COLOR_F color) {
    auto& cmd = AddCommand(DrawCommandType::FillRect);
    cmd.rect = rect;
    cmd.color = color;
}

void DisplayListRecorder::FillQuad(const D2D1_POINT_2F pts[4], D2D1_COLOR_F color) {
    QuadRef quad;
    for (int i = 0; i < 4; ++i) quad.pts[i] = pts[i];
    list_.quad_refs.push_back(quad);
    auto& cmd = AddCommand(DrawCommandType::FillQuad);
    cmd.quad_index = (uint32_t)(list_.quad_refs.size() - 1);
    cmd.color = color;
}

void DisplayListRecorder::DrawRect(D2D1_RECT_F rect, D2D1_COLOR_F color, float strokeWidth) {
    auto& cmd = AddCommand(DrawCommandType::DrawRect);
    cmd.rect = rect;
    cmd.color = color;
    cmd.stroke_width = strokeWidth;
}

void DisplayListRecorder::FillRoundedRect(D2D1_RECT_F rect, float rx, float ry, D2D1_COLOR_F color) {
    auto& cmd = AddCommand(DrawCommandType::FillRoundedRect);
    cmd.rect = rect;
    cmd.radius_x = rx;
    cmd.radius_y = ry;
    cmd.color = color;
}

void DisplayListRecorder::DrawRoundedRect(D2D1_RECT_F rect, float rx, float ry,
                                          D2D1_COLOR_F color, float strokeWidth) {
    auto& cmd = AddCommand(DrawCommandType::DrawRoundedRect);
    cmd.rect = rect;
    cmd.radius_x = rx;
    cmd.radius_y = ry;
    cmd.color = color;
    cmd.stroke_width = strokeWidth;
}

void DisplayListRecorder::DrawBlurredRoundedRect(D2D1_RECT_F rect, float rx, float ry,
                                                 float blurRadius, D2D1_COLOR_F color) {
    auto& cmd = AddCommand(DrawCommandType::DrawBlurredRoundedRect);
    cmd.rect = rect;
    cmd.radius_x = rx;
    cmd.radius_y = ry;
    cmd.blur_radius = blurRadius;
    cmd.color = color;
}

void DisplayListRecorder::DrawLine(D2D1_POINT_2F p0, D2D1_POINT_2F p1,
                                   D2D1_COLOR_F color, float strokeWidth) {
    auto& cmd = AddCommand(DrawCommandType::DrawLine);
    cmd.p0 = p0;
    cmd.p1 = p1;
    cmd.color = color;
    cmd.stroke_width = strokeWidth;
}

void DisplayListRecorder::DrawText(std::wstring text, D2D1_RECT_F rect, TextStyle style) {
    auto& cmd = AddCommand(DrawCommandType::DrawText);
    cmd.rect = rect;
    cmd.text_index = AddText(std::move(text));
    cmd.text_style = style;
}

void DisplayListRecorder::DrawImage(ImageRef image, D2D1_RECT_F dst,
                                    ImageSampling sampling, float opacity) {
    auto& cmd = AddCommand(DrawCommandType::DrawImage);
    cmd.rect = dst;
    cmd.image_ref_index = AddImageRef(image);
    cmd.sampling = sampling;
    cmd.opacity = opacity;
}

void DisplayListRecorder::FillImagePattern(ImageRef image, D2D1_RECT_F rect) {
    auto& cmd = AddCommand(DrawCommandType::FillImagePattern);
    cmd.rect = rect;
    cmd.image_ref_index = AddImageRef(image);
    cmd.sampling = ImageSampling::Nearest;
}

void DisplayListRecorder::FillGradient(GradientRef gradient, D2D1_RECT_F rect, float radius) {
    auto& cmd = AddCommand(DrawCommandType::FillGradient);
    cmd.rect = rect;
    cmd.radius_x = radius;
    cmd.gradient_ref_index = AddGradientRef(std::move(gradient));
}

void DisplayListRecorder::DrawSvgIcon(SvgIconRef icon, D2D1_RECT_F dst, D2D1_COLOR_F color) {
    auto& cmd = AddCommand(DrawCommandType::DrawSvgIcon);
    cmd.rect = dst;
    cmd.color = color;
    cmd.svg_ref_index = AddSvgIconRef(std::move(icon));
}

void DisplayListRecorder::DrawSvgDocument(SvgDocumentRef doc, D2D1_MATRIX_3X2_F transform) {
    auto& cmd = AddCommand(DrawCommandType::DrawSvgDocument);
    cmd.transform = transform;
    cmd.svg_document_ref_index = AddSvgDocumentRef(std::move(doc));
}

void DisplayListRecorder::DrawSvgTextRuns(SvgTextRunListRef textRuns) {
    auto& cmd = AddCommand(DrawCommandType::DrawSvgTextRuns);
    cmd.svg_text_ref_index = AddSvgTextRunRef(std::move(textRuns));
}

void DisplayListRecorder::DrawBackdropBlur(D2D1_RECT_F rect, float radius, float blurRadius) {
    auto& cmd = AddCommand(DrawCommandType::DrawBackdropBlur);
    cmd.rect = rect;
    cmd.radius_x = radius;
    cmd.blur_radius = blurRadius;
}

void DisplayListRecorder::OwnResource(ResourceKey key) {
    list_.AddOwnedResource(key);
}

DisplayList DisplayListRecorder::Finish() {
    DisplayList out = std::move(list_);
    list_ = {};
    return out;
}

uint32_t DisplayListRecorder::AddText(std::wstring text) {
    const uint32_t index = static_cast<uint32_t>(list_.text_pool.size());
    list_.text_pool.push_back(std::move(text));
    return index;
}

uint32_t DisplayListRecorder::AddImageRef(ImageRef image) {
    const uint32_t index = static_cast<uint32_t>(list_.image_refs.size());
    list_.image_refs.push_back(image);
    return index;
}

uint32_t DisplayListRecorder::AddGradientRef(GradientRef gradient) {
    const uint32_t index = static_cast<uint32_t>(list_.gradient_refs.size());
    list_.gradient_refs.push_back(std::move(gradient));
    return index;
}

uint32_t DisplayListRecorder::AddSvgIconRef(SvgIconRef icon) {
    const uint32_t index = static_cast<uint32_t>(list_.svg_icon_refs.size());
    list_.svg_icon_refs.push_back(std::move(icon));
    return index;
}

uint32_t DisplayListRecorder::AddSvgDocumentRef(SvgDocumentRef doc) {
    const uint32_t index = static_cast<uint32_t>(list_.svg_document_refs.size());
    list_.svg_document_refs.push_back(std::move(doc));
    return index;
}

uint32_t DisplayListRecorder::AddSvgTextRunRef(SvgTextRunListRef textRuns) {
    const uint32_t index = static_cast<uint32_t>(list_.svg_text_refs.size());
    list_.svg_text_refs.push_back(std::move(textRuns));
    return index;
}

DrawCommand& DisplayListRecorder::AddCommand(DrawCommandType type) {
    DrawCommand cmd;
    cmd.type = type;
    list_.commands.push_back(cmd);
    return list_.commands.back();
}

} // namespace ui
