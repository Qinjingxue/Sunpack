#include "script_runtime.h"

#include <cstring>
#include <new>
#include <utility>

namespace ui::uix {

namespace {

// C trampoline for the Proxy `get` trap.
//
// Called by the JS engine as: handler.get(target, key, receiver)
// We forward to the C++ ScriptRuntime stored on the JSContext via opaque.
JSValue ProxyGetTrap(JSContext* ctx, JSValueConst /*this_val*/,
                     int argc, JSValueConst* argv) {
    if (argc < 2) return JS_UNDEFINED;
    JSValueConst target = argv[0];
    JSValueConst key    = argv[1];

    auto* self = static_cast<ScriptRuntime*>(JS_GetContextOpaque(ctx));

    // Computed key fast-path: if this (target, key) is registered as a
    // computed, the cached/recomputed value comes from GetComputed and the
    // outer effect is tracked there — bypass plain JS_GetProperty so we
    // never read whatever (probably undefined) sits on the data object
    // for this name.
    if (self && !JS_IsSymbol(key)) {
        const char* keyStr = JS_ToCString(ctx, key);
        if (!keyStr) return JS_EXCEPTION;
        void* tp = JS_VALUE_GET_PTR(target);
        if (self->IsComputed(tp, keyStr)) {
            JSValue r = self->GetComputed(tp, keyStr);
            JS_FreeCString(ctx, keyStr);
            return r;
        }
        self->TrackRead(tp, keyStr);
        JS_FreeCString(ctx, keyStr);
    }

    // Pass-through: return target[key].
    JSAtom atom = JS_ValueToAtom(ctx, key);
    if (atom == JS_ATOM_NULL) return JS_EXCEPTION;
    JSValue result = JS_GetProperty(ctx, target, atom);
    JS_FreeAtom(ctx, atom);
    return result;
}

// C trampoline for the Proxy `set` trap.
//
// Called as: handler.set(target, key, value, receiver) → must return Boolean.
JSValue ProxySetTrap(JSContext* ctx, JSValueConst /*this_val*/,
                     int argc, JSValueConst* argv) {
    if (argc < 3) return JS_FALSE;
    JSValueConst target = argv[0];
    JSValueConst key    = argv[1];
    JSValueConst value  = argv[2];

    auto* self = static_cast<ScriptRuntime*>(JS_GetContextOpaque(ctx));

    // The UI writes a few unchanged scalar values while switching pages.
    // Do not notify reactive effects for a strict-equal primitive; doing so
    // repeatedly rebinds controls, invalidates layout and schedules paints.
    // Object/array writes must retain reference/identity update semantics.
    JSAtom atom = JS_ValueToAtom(ctx, key);
    if (atom == JS_ATOM_NULL) return JS_EXCEPTION;
    if (JS_IsString(value) || JS_IsNumber(value) || JS_IsBool(value) ||
        JS_IsNull(value) || JS_IsUndefined(value)) {
        JSValue previous = JS_GetProperty(ctx, target, atom);
        if (JS_IsException(previous)) {
            JS_FreeAtom(ctx, atom);
            return JS_EXCEPTION;
        }
        bool same = JS_IsStrictEqual(ctx, previous, value);
        JS_FreeValue(ctx, previous);
        if (same) {
            JS_FreeAtom(ctx, atom);
            return JS_TRUE;
        }
    }
    // Pass-through write: target[key] = value (dup so target retains ownership).
    int rc = JS_SetProperty(ctx, target, atom, JS_DupValue(ctx, value));
    JS_FreeAtom(ctx, atom);
    if (rc < 0) return JS_EXCEPTION;

    // Trigger dependent effects after the write lands.
    if (self && !JS_IsSymbol(key)) {
        const char* keyStr = JS_ToCString(ctx, key);
        if (!keyStr) return JS_EXCEPTION;
        self->TriggerWrite(JS_VALUE_GET_PTR(target), keyStr);
        JS_FreeCString(ctx, keyStr);
    }

    return JS_TRUE;
}

}  // namespace

// ---- ScriptRuntime ----

ScriptRuntime::ScriptRuntime() {
    rt_  = JS_NewRuntime();
    if (!rt_) throw std::bad_alloc();
    ctx_ = JS_NewContext(rt_);
    if (!ctx_) {
        JS_FreeRuntime(rt_);
        throw std::bad_alloc();
    }
    JS_SetContextOpaque(ctx_, this);

    // Pre-build the trap functions so MakeReactive can reuse them.
    trapGet_ = JS_NewCFunction(ctx_, &ProxyGetTrap, "get", 3);
    if (!JS_IsException(trapGet_)) {
        trapSet_ = JS_NewCFunction(ctx_, &ProxySetTrap, "set", 4);
        if (!JS_IsException(trapSet_)) return;
        JS_FreeValue(ctx_, trapGet_);
    }
    JS_FreeContext(ctx_);
    JS_FreeRuntime(rt_);
    throw std::bad_alloc();
}

ScriptRuntime::~ScriptRuntime() {
    // Order matters: drop effect closures (which may hold JSValues via
    // user-side captures) before tearing down the runtime.
    effects_.clear();
    depMap_.clear();

    // Free computeds' refs while ctx_ is still alive.
    for (auto& kv : computeds_) {
        auto& c = *kv.second;
        if (!JS_IsUndefined(c.userFn))      JS_FreeValue(ctx_, c.userFn);
        if (!JS_IsUndefined(c.thisObj))     JS_FreeValue(ctx_, c.thisObj);
        if (!JS_IsUndefined(c.cachedValue)) JS_FreeValue(ctx_, c.cachedValue);
    }
    computeds_.clear();
    ClearTemplateClosures();

    JS_FreeValue(ctx_, trapGet_);
    JS_FreeValue(ctx_, trapSet_);

    if (ctx_) JS_FreeContext(ctx_);
    if (rt_)  JS_FreeRuntime(rt_);
}

namespace {
std::string FormatException(JSContext* ctx, JSValue exc, bool includeStack) {
    auto freeString = [ctx](const char* s) { JS_FreeCString(ctx, s); };
    std::unique_ptr<const char, decltype(freeString)> message(
        JS_ToCString(ctx, exc), freeString);
    std::unique_ptr<const char, decltype(freeString)> trace(nullptr, freeString);
    if (message && includeStack && JS_IsObject(exc)) {
        JSValue stack = JS_GetPropertyStr(ctx, exc, "stack");
        if (!JS_IsUndefined(stack) && !JS_IsException(stack)) {
            trace.reset(JS_ToCString(ctx, stack));
        }
        JS_FreeValue(ctx, stack);
    }
    JS_FreeValue(ctx, exc);
    // Error coercion and stack getters can execute JS, and allocation can fail.
    if (JS_HasException(ctx)) JS_FreeValue(ctx, JS_GetException(ctx));
    std::string out = message ? message.get() : "(no message)";
    if (trace) {
        out += '\n';
        out += trace.get();
    }
    return out;
}
}  // namespace

std::string TakeExceptionMessage(JSContext* ctx, bool includeStack) {
    if (!JS_HasException(ctx)) return "(no message)";
    return FormatException(ctx, JS_GetException(ctx), includeStack);
}

bool ScriptRuntime::Eval(const std::string& source, const std::string& filename) {
    JSValue v = JS_Eval(ctx_, source.c_str(), source.size(),
                        filename.c_str(), JS_EVAL_TYPE_GLOBAL);
    if (JS_IsException(v)) {
        lastError_ = TakeExceptionMessage(ctx_, true);
        JS_FreeValue(ctx_, v);
        return false;
    }
    JS_FreeValue(ctx_, v);
    lastError_.clear();
    return true;
}

ScriptRuntime::ModuleEvalResult
ScriptRuntime::EvalModule(const std::string& source, const std::string& filename) {
    ModuleEvalResult r;

    // 1) Compile only — produces a JS_TAG_MODULE value wrapping JSModuleDef*.
    JSValue compiled = JS_Eval(ctx_, source.c_str(), source.size(),
                               filename.c_str(),
                               JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);
    if (JS_IsException(compiled)) {
        lastError_ = TakeExceptionMessage(ctx_, true);
        return r;
    }

    // Stash the JSModuleDef* before EvalFunction consumes the value.
    JSModuleDef* mod = static_cast<JSModuleDef*>(JS_VALUE_GET_PTR(compiled));

    // 2) Evaluate the module's top-level body. JS_EvalFunction takes
    //    ownership of `compiled` (don't free it ourselves).
    JSValue evalRet = JS_EvalFunction(ctx_, compiled);
    if (JS_IsException(evalRet) || JS_HasException(ctx_)) {
        JS_FreeValue(ctx_, evalRet);
        lastError_ = TakeExceptionMessage(ctx_, true);
        return r;
    }
    // Module execution can reject its promise even without any async work.
    if (JS_PromiseState(ctx_, evalRet) == JS_PROMISE_REJECTED) {
        JSValue reason = JS_PromiseResult(ctx_, evalRet);
        JS_FreeValue(ctx_, evalRet);
        lastError_ = FormatException(ctx_, reason, true);
        return r;
    }
    JS_FreeValue(ctx_, evalRet);

    // 3) Extract the `default` export from the module's namespace.
    JSValue ns = JS_GetModuleNamespace(ctx_, mod);
    if (JS_IsException(ns)) {
        lastError_ = TakeExceptionMessage(ctx_, true);
        return r;
    }

    JSValue def = JS_GetPropertyStr(ctx_, ns, "default");
    JS_FreeValue(ctx_, ns);

    if (JS_IsException(def)) {
        lastError_ = TakeExceptionMessage(ctx_, true);
        return r;
    }
    if (JS_IsUndefined(def)) {
        lastError_ = "<script>: missing `export default` (Vue 3 Options API "
                     "requires component options to be the default export)";
        return r;
    }

    r.defaultExport = def;
    r.ok = true;
    lastError_.clear();
    return r;
}

JSValue ScriptRuntime::CompileBindingClosure(const std::string& jsExpr,
                                              const std::string& filename) {
    // Wrap so that JS_Eval returns the function value directly.
    std::string src;
    src.reserve(jsExpr.size() + 32);
    src += "(function(){return (";
    src += jsExpr;
    src += ");})";
    JSValue v = JS_Eval(ctx_, src.c_str(), src.size(),
                        filename.c_str(), JS_EVAL_TYPE_GLOBAL);
    if (JS_IsException(v)) {
        lastError_ = TakeExceptionMessage(ctx_, true);
    } else {
        lastError_.clear();
    }
    return v;
}

JSValue ScriptRuntime::CompileHandlerClosure(const std::string& jsExpr,
                                              const std::string& filename) {
    // Vue 3 event handler semantics:
    //   `@click="inc"`           → bare ident → auto-call inc($event)
    //   `@click="inc()"`         → already a call, ignore $event
    //   `@click="count = count + 1"` → assignment, no auto-call
    // The wrapper evaluates EXPR; if the result is a function, calls it
    // with $event. Statement-shaped EXPR (assignment) is OK in expression
    // position — the result is the assigned value, not a function.
    //
    // Use __r.call(this, $event) so bare-ident form (post-rewrite EXPR is
    // `this.inc`) keeps `this` bound to the reactive state proxy. Plain
    // `__r($event)` would lose that binding and a `this.count++` body would
    // throw in strict mode / clobber globals in sloppy.
    std::string src;
    src.reserve(jsExpr.size() + 96);
    src += "(function($event){var __r=(";
    src += jsExpr;
    src += ");if(typeof __r==='function')__r.call(this,$event);})";
    JSValue v = JS_Eval(ctx_, src.c_str(), src.size(),
                        filename.c_str(), JS_EVAL_TYPE_GLOBAL);
    if (JS_IsException(v)) {
        lastError_ = TakeExceptionMessage(ctx_, true);
    } else {
        lastError_.clear();
    }
    return v;
}

void ScriptRuntime::ClearTemplateClosures() {
    for (auto& entry : templateClosures_) JS_FreeValue(ctx_, entry.second);
    templateClosures_.clear();
    templateSourceBytes_ = 0;
}

JSValue ScriptRuntime::CompileTemplateClosure(const std::string& source, const std::string& filename) {
    auto key = filename + '\n' + source;
    auto found = templateClosures_.find(key);
    if (found != templateClosures_.end()) {
        lastError_.clear();
        return JS_DupValue(ctx_, found->second);
    }
    JSValue value = JS_Eval(ctx_, source.c_str(), source.size(), filename.c_str(), JS_EVAL_TYPE_GLOBAL);
    if (JS_IsException(value)) {
        lastError_ = TakeExceptionMessage(ctx_, true);
        return value;
    }
    lastError_.clear();
    if (key.size() <= 8192) {
        if (templateClosures_.size() >= 512 || templateSourceBytes_ + key.size() > 131072) ClearTemplateClosures();
        templateSourceBytes_ += key.size();
        templateClosures_.emplace(std::move(key), JS_DupValue(ctx_, value));
    }
    return value;
}

JSValue ScriptRuntime::CompileLoopBindingClosure(const std::string& jsExpr,
                                                  const std::string& loopVar,
                                                  const std::string& indexVar,
                                                  const std::string& filename) {
    std::string params = loopVar;
    if (!indexVar.empty()) { params += ","; params += indexVar; }

    std::string src;
    src.reserve(jsExpr.size() + params.size() + 32);
    src += "(function(";
    src += params;
    src += "){return (";
    src += jsExpr;
    src += ");})";
    return CompileTemplateClosure(src, filename);
}

JSValue ScriptRuntime::CompileLoopHandlerClosure(const std::string& jsExpr,
                                                  const std::string& loopVar,
                                                  const std::string& indexVar,
                                                  const std::string& filename) {
    std::string params = loopVar;
    if (!indexVar.empty()) { params += ","; params += indexVar; }
    params += ",$event";

    std::string src;
    src.reserve(jsExpr.size() + params.size() + 96);
    src += "(function(";
    src += params;
    src += "){var __r=(";
    src += jsExpr;
    src += ");if(typeof __r==='function')__r.call(this,$event);})";
    return CompileTemplateClosure(src, filename);
}

JSValue ScriptRuntime::CompileLoopBindingClosure(const std::string& jsExpr,
                                                  const std::vector<std::string>& paramNames,
                                                  const std::string& filename) {
    std::string params;
    for (size_t i = 0; i < paramNames.size(); ++i) {
        if (paramNames[i].empty()) continue;
        if (!params.empty()) params += ",";
        params += paramNames[i];
    }
    std::string src;
    src.reserve(jsExpr.size() + params.size() + 32);
    src += "(function(";
    src += params;
    src += "){return (";
    src += jsExpr;
    src += ");})";
    return CompileTemplateClosure(src, filename);
}

JSValue ScriptRuntime::CompileLoopHandlerClosure(const std::string& jsExpr,
                                                  const std::vector<std::string>& paramNames,
                                                  const std::string& filename) {
    std::string params;
    for (size_t i = 0; i < paramNames.size(); ++i) {
        if (paramNames[i].empty()) continue;
        if (!params.empty()) params += ",";
        params += paramNames[i];
    }
    if (!params.empty()) params += ",";
    params += "$event";

    std::string src;
    src.reserve(jsExpr.size() + params.size() + 96);
    src += "(function(";
    src += params;
    src += "){var __r=(";
    src += jsExpr;
    src += ");if(typeof __r==='function')__r.call(this,$event);})";
    return CompileTemplateClosure(src, filename);
}

JSValue ScriptRuntime::MakeReactive(JSValueConst target) {
    // The handler owns a reference to each trap.
    JSValue handler = JS_NewObject(ctx_);
    if (JS_IsException(handler)) return handler;
    if (JS_SetPropertyStr(ctx_, handler, "get", JS_DupValue(ctx_, trapGet_)) < 0 ||
        JS_SetPropertyStr(ctx_, handler, "set", JS_DupValue(ctx_, trapSet_)) < 0) {
        JS_FreeValue(ctx_, handler);
        return JS_EXCEPTION;
    }

    // new Proxy(target, handler)
    JSValue global    = JS_GetGlobalObject(ctx_);
    JSValue proxyCtor = JS_GetPropertyStr(ctx_, global, "Proxy");

    JSValueConst args[2] = { target, handler };
    JSValue proxy = JS_IsException(proxyCtor)
        ? JS_EXCEPTION : JS_CallConstructor(ctx_, proxyCtor, 2, args);

    JS_FreeValue(ctx_, handler);
    JS_FreeValue(ctx_, proxyCtor);
    JS_FreeValue(ctx_, global);

    return proxy;
}

uint64_t ScriptRuntime::WatchEffect(Effect fn) {
    uint64_t id = nextEffectId_++;
    effects_.emplace(id, std::move(fn));

    uint64_t prev = activeEffectId_;
    activeEffectId_ = id;
    auto it = effects_.find(id);
    if (it != effects_.end()) {
        it->second();   // initial run; collects deps via trap callbacks
    }
    activeEffectId_ = prev;

    return id;
}

void ScriptRuntime::DisposeEffect(uint64_t id) {
    effects_.erase(id);
    // Strip from every dep set (linear in dep count; fine for v0).
    for (auto it = depMap_.begin(); it != depMap_.end(); ) {
        it->second.erase(id);
        if (it->second.empty()) it = depMap_.erase(it);
        else ++it;
    }
}

void ScriptRuntime::TrackRead(void* target_ptr, const std::string& key) {
    if (activeEffectId_ == 0) return;
    depMap_[DepKey{target_ptr, key}].insert(activeEffectId_);
}

void ScriptRuntime::TriggerWrite(void* target_ptr, const std::string& key) {
    auto it = depMap_.find(DepKey{target_ptr, key});
    if (it == depMap_.end()) return;

    // Snapshot the effect set: re-running effects re-collects deps and may
    // mutate depMap_ underneath us.
    std::set<uint64_t> snapshot = it->second;
    for (uint64_t id : snapshot) {
        auto fnIt = effects_.find(id);
        if (fnIt == effects_.end()) continue;

        // Save/restore activeEffectId_ so re-runs nested under another
        // tracking effect don't get cross-contaminated.
        uint64_t prev = activeEffectId_;
        activeEffectId_ = id;
        fnIt->second();
        activeEffectId_ = prev;
    }
}

bool ScriptRuntime::IsComputed(void* target_ptr, const std::string& key) const {
    return computeds_.find(DepKey{target_ptr, key}) != computeds_.end();
}

bool ScriptRuntime::DefineComputed(void* target_ptr, const std::string& key,
                                   JSValueConst userFn, JSValueConst thisObj) {
    auto ref = std::make_unique<ComputedRef>();
    ref->userFn  = JS_DupValue(ctx_, userFn);
    ref->thisObj = JS_DupValue(ctx_, thisObj);
    ref->target  = target_ptr;
    ref->key     = key;
    ref->dirty   = true;

    // Allocate the watcher effect id directly. We don't go through
    // WatchEffect because its "run fn once with tracking" contract would
    // call our scheduler body (mark-dirty + trigger) before any deps were
    // collected. Instead we register the effect entry then run userFn
    // once manually with activeEffectId_=watcherId so the user's reads
    // through the proxy land in depMap_ keyed against this watcher.
    ref->watcherId = nextEffectId_++;
    ComputedRef* refPtr = ref.get();
    effects_.emplace(ref->watcherId, [this, refPtr]() {
        // A dep changed → invalidate the cache and notify every effect
        // that depends on this computed. We do NOT recompute here; that
        // happens lazily on next GetComputed call.
        if (!refPtr->dirty) {
            refPtr->dirty = true;
            TriggerWrite(refPtr->target, refPtr->key);
        }
    });

    // Initial dep collection + cache seed.
    uint64_t prev = activeEffectId_;
    activeEffectId_ = ref->watcherId;
    JSValue v = JS_Call(ctx_, ref->userFn, ref->thisObj, 0, nullptr);
    activeEffectId_ = prev;

    bool ok = true;
    if (JS_IsException(v)) {
        JSValue error = JS_GetException(ctx_);
        if (JS_IsUncatchableError(error)) {
            JS_Throw(ctx_, error);
            ok = false;
        } else {
            // A later read can retry after another computed is registered.
            lastError_ = FormatException(ctx_, error, true);
        }
    } else {
        ref->cachedValue = v;
        ref->dirty       = false;
    }

    computeds_.emplace(DepKey{target_ptr, key}, std::move(ref));
    return ok;
}

JSValue ScriptRuntime::GetComputed(void* target_ptr, const std::string& key) {
    auto it = computeds_.find(DepKey{target_ptr, key});
    if (it == computeds_.end()) return JS_UNDEFINED;
    auto& ref = *it->second;
    // Keep the outer dependency even if evaluation fails this time.
    TrackRead(target_ptr, key);

    if (ref.dirty) {
        // Recompute under the watcher's effect id so reads register
        // against the watcher (not whichever outer effect is currently
        // active). Without this swap, a binding that reads the computed
        // would get its id sprayed onto every dep the user fn touches —
        // doubling re-runs and breaking computed-of-computed semantics.
        uint64_t prev = activeEffectId_;
        activeEffectId_ = ref.watcherId;
        JSValue old = ref.cachedValue;
        JSValue v   = JS_Call(ctx_, ref.userFn, ref.thisObj, 0, nullptr);
        activeEffectId_ = prev;

        if (JS_IsException(v)) {
            JSValue error = JS_GetException(ctx_);
            if (JS_IsUncatchableError(error)) return JS_Throw(ctx_, error);
            lastError_ = FormatException(ctx_, error, true);
            // Leave dirty=true so next read retries; keep prior cached value.
        } else {
            ref.cachedValue = v;
            JS_FreeValue(ctx_, old);
            ref.dirty = false;
        }
    }

    return JS_DupValue(ctx_, ref.cachedValue);
}

}  // namespace ui::uix
