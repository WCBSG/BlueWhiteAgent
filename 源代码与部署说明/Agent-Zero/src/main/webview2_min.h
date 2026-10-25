
#ifndef AGENT_WEBVIEW2_MIN_H
#define AGENT_WEBVIEW2_MIN_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <objbase.h>

#ifndef MIDL_INTERFACE
#define MIDL_INTERFACE(x) struct __declspec(uuid(x)) __declspec(novtable)
#endif

typedef struct EventRegistrationToken { LONGLONG value; } EventRegistrationToken;

struct ICoreWebView2Environment;
struct ICoreWebView2CreateCoreWebView2ControllerCompletedHandler;
struct ICoreWebView2WebResourceResponse;
struct ICoreWebView2NewBrowserVersionAvailableEventHandler;
struct ICoreWebView2Controller;
struct ICoreWebView2ZoomFactorChangedEventHandler;
struct ICoreWebView2MoveFocusRequestedEventHandler;
struct ICoreWebView2FocusChangedEventHandler;
struct ICoreWebView2AcceleratorKeyPressedEventHandler;
struct ICoreWebView2;
struct ICoreWebView2Settings;
struct ICoreWebView2NavigationStartingEventHandler;
struct ICoreWebView2ContentLoadingEventHandler;
struct ICoreWebView2SourceChangedEventHandler;
struct ICoreWebView2HistoryChangedEventHandler;
struct ICoreWebView2NavigationCompletedEventHandler;
struct ICoreWebView2ScriptDialogOpeningEventHandler;
struct ICoreWebView2PermissionRequestedEventHandler;
struct ICoreWebView2ProcessFailedEventHandler;
struct ICoreWebView2AddScriptToExecuteOnDocumentCreatedCompletedHandler;
struct ICoreWebView2ExecuteScriptCompletedHandler;
struct ICoreWebView2CapturePreviewCompletedHandler;
struct ICoreWebView2WebMessageReceivedEventHandler;
struct ICoreWebView2CallDevToolsProtocolMethodCompletedHandler;
struct ICoreWebView2DevToolsProtocolEventReceiver;
struct ICoreWebView2NewWindowRequestedEventHandler;
struct ICoreWebView2DocumentTitleChangedEventHandler;
struct ICoreWebView2ContainsFullScreenElementChangedEventHandler;
struct ICoreWebView2WebResourceRequestedEventHandler;
struct ICoreWebView2WindowCloseRequestedEventHandler;
struct ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler;
struct ICoreWebView2NewWindowRequestedEventArgs;
struct ICoreWebView2Deferral;
struct ICoreWebView2WindowFeatures;
struct ICoreWebView2EnvironmentOptions;

typedef
enum COREWEBVIEW2_MOVE_FOCUS_REASON
    {
        COREWEBVIEW2_MOVE_FOCUS_REASON_PROGRAMMATIC	= 0,
        COREWEBVIEW2_MOVE_FOCUS_REASON_NEXT	= ( COREWEBVIEW2_MOVE_FOCUS_REASON_PROGRAMMATIC + 1 ) ,
        COREWEBVIEW2_MOVE_FOCUS_REASON_PREVIOUS	= ( COREWEBVIEW2_MOVE_FOCUS_REASON_NEXT + 1 )
    } 	COREWEBVIEW2_MOVE_FOCUS_REASON;

typedef
enum COREWEBVIEW2_CAPTURE_PREVIEW_IMAGE_FORMAT
    {
        COREWEBVIEW2_CAPTURE_PREVIEW_IMAGE_FORMAT_PNG	= 0,
        COREWEBVIEW2_CAPTURE_PREVIEW_IMAGE_FORMAT_JPEG	= ( COREWEBVIEW2_CAPTURE_PREVIEW_IMAGE_FORMAT_PNG + 1 )
    } 	COREWEBVIEW2_CAPTURE_PREVIEW_IMAGE_FORMAT;

typedef
enum COREWEBVIEW2_WEB_RESOURCE_CONTEXT
    {
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL	= 0,
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_DOCUMENT	= ( COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL + 1 ) ,
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_STYLESHEET	= ( COREWEBVIEW2_WEB_RESOURCE_CONTEXT_DOCUMENT + 1 ) ,
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_IMAGE	= ( COREWEBVIEW2_WEB_RESOURCE_CONTEXT_STYLESHEET + 1 ) ,
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_MEDIA	= ( COREWEBVIEW2_WEB_RESOURCE_CONTEXT_IMAGE + 1 ) ,
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_FONT	= ( COREWEBVIEW2_WEB_RESOURCE_CONTEXT_MEDIA + 1 ) ,
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_SCRIPT	= ( COREWEBVIEW2_WEB_RESOURCE_CONTEXT_FONT + 1 ) ,
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_XML_HTTP_REQUEST	= ( COREWEBVIEW2_WEB_RESOURCE_CONTEXT_SCRIPT + 1 ) ,
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_FETCH	= ( COREWEBVIEW2_WEB_RESOURCE_CONTEXT_XML_HTTP_REQUEST + 1 ) ,
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_TEXT_TRACK	= ( COREWEBVIEW2_WEB_RESOURCE_CONTEXT_FETCH + 1 ) ,
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_EVENT_SOURCE	= ( COREWEBVIEW2_WEB_RESOURCE_CONTEXT_TEXT_TRACK + 1 ) ,
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_WEBSOCKET	= ( COREWEBVIEW2_WEB_RESOURCE_CONTEXT_EVENT_SOURCE + 1 ) ,
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_MANIFEST	= ( COREWEBVIEW2_WEB_RESOURCE_CONTEXT_WEBSOCKET + 1 ) ,
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_SIGNED_EXCHANGE	= ( COREWEBVIEW2_WEB_RESOURCE_CONTEXT_MANIFEST + 1 ) ,
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_PING	= ( COREWEBVIEW2_WEB_RESOURCE_CONTEXT_SIGNED_EXCHANGE + 1 ) ,
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_CSP_VIOLATION_REPORT	= ( COREWEBVIEW2_WEB_RESOURCE_CONTEXT_PING + 1 ) ,
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_OTHER	= ( COREWEBVIEW2_WEB_RESOURCE_CONTEXT_CSP_VIOLATION_REPORT + 1 )
    } 	COREWEBVIEW2_WEB_RESOURCE_CONTEXT;

MIDL_INTERFACE("b96d755e-0319-4e92-a296-23436f46a1fc")
    ICoreWebView2Environment : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE CreateCoreWebView2Controller(
            HWND parentWindow,
            ICoreWebView2CreateCoreWebView2ControllerCompletedHandler *handler) = 0;

        virtual HRESULT STDMETHODCALLTYPE CreateWebResourceResponse(
             IStream *content,
             int statusCode,
             LPCWSTR reasonPhrase,
             LPCWSTR headers,
             ICoreWebView2WebResourceResponse **response) = 0;

        virtual  HRESULT STDMETHODCALLTYPE get_BrowserVersionString(
             LPWSTR *versionInfo) = 0;

        virtual HRESULT STDMETHODCALLTYPE add_NewBrowserVersionAvailable(
             ICoreWebView2NewBrowserVersionAvailableEventHandler *eventHandler,
             EventRegistrationToken *token) = 0;

        virtual HRESULT STDMETHODCALLTYPE remove_NewBrowserVersionAvailable(
             EventRegistrationToken token) = 0;

    };

MIDL_INTERFACE("4d00c0d1-9434-4eb6-8078-8697a560334f")
    ICoreWebView2Controller : public IUnknown
    {
    public:
        virtual  HRESULT STDMETHODCALLTYPE get_IsVisible(
             BOOL *isVisible) = 0;

        virtual  HRESULT STDMETHODCALLTYPE put_IsVisible(
             BOOL isVisible) = 0;

        virtual  HRESULT STDMETHODCALLTYPE get_Bounds(
             RECT *bounds) = 0;

        virtual  HRESULT STDMETHODCALLTYPE put_Bounds(
             RECT bounds) = 0;

        virtual  HRESULT STDMETHODCALLTYPE get_ZoomFactor(
             double *zoomFactor) = 0;

        virtual  HRESULT STDMETHODCALLTYPE put_ZoomFactor(
             double zoomFactor) = 0;

        virtual HRESULT STDMETHODCALLTYPE add_ZoomFactorChanged(
             ICoreWebView2ZoomFactorChangedEventHandler *eventHandler,
             EventRegistrationToken *token) = 0;

        virtual HRESULT STDMETHODCALLTYPE remove_ZoomFactorChanged(
             EventRegistrationToken token) = 0;

        virtual HRESULT STDMETHODCALLTYPE SetBoundsAndZoomFactor(
             RECT bounds,
             double zoomFactor) = 0;

        virtual HRESULT STDMETHODCALLTYPE MoveFocus(
             COREWEBVIEW2_MOVE_FOCUS_REASON reason) = 0;

        virtual HRESULT STDMETHODCALLTYPE add_MoveFocusRequested(
             ICoreWebView2MoveFocusRequestedEventHandler *eventHandler,
             EventRegistrationToken *token) = 0;

        virtual HRESULT STDMETHODCALLTYPE remove_MoveFocusRequested(
             EventRegistrationToken token) = 0;

        virtual HRESULT STDMETHODCALLTYPE add_GotFocus(
             ICoreWebView2FocusChangedEventHandler *eventHandler,
             EventRegistrationToken *token) = 0;

        virtual HRESULT STDMETHODCALLTYPE remove_GotFocus(
             EventRegistrationToken token) = 0;

        virtual HRESULT STDMETHODCALLTYPE add_LostFocus(
             ICoreWebView2FocusChangedEventHandler *eventHandler,
             EventRegistrationToken *token) = 0;

        virtual HRESULT STDMETHODCALLTYPE remove_LostFocus(
             EventRegistrationToken token) = 0;

        virtual HRESULT STDMETHODCALLTYPE add_AcceleratorKeyPressed(
             ICoreWebView2AcceleratorKeyPressedEventHandler *eventHandler,
             EventRegistrationToken *token) = 0;

        virtual HRESULT STDMETHODCALLTYPE remove_AcceleratorKeyPressed(
             EventRegistrationToken token) = 0;

        virtual  HRESULT STDMETHODCALLTYPE get_ParentWindow(
             HWND *parentWindow) = 0;

        virtual  HRESULT STDMETHODCALLTYPE put_ParentWindow(
             HWND parentWindow) = 0;

        virtual HRESULT STDMETHODCALLTYPE NotifyParentWindowPositionChanged( void) = 0;

        virtual HRESULT STDMETHODCALLTYPE Close( void) = 0;

        virtual  HRESULT STDMETHODCALLTYPE get_CoreWebView2(
             ICoreWebView2 **coreWebView2) = 0;

    };

MIDL_INTERFACE("e562e4f0-d7fa-43ac-8d71-c05150499f00")
    ICoreWebView2Settings : public IUnknown
    {
    public:
        virtual  HRESULT STDMETHODCALLTYPE get_IsScriptEnabled(
             BOOL *isScriptEnabled) = 0;

        virtual  HRESULT STDMETHODCALLTYPE put_IsScriptEnabled(
             BOOL isScriptEnabled) = 0;

        virtual  HRESULT STDMETHODCALLTYPE get_IsWebMessageEnabled(
             BOOL *isWebMessageEnabled) = 0;

        virtual  HRESULT STDMETHODCALLTYPE put_IsWebMessageEnabled(
             BOOL isWebMessageEnabled) = 0;

        virtual  HRESULT STDMETHODCALLTYPE get_AreDefaultScriptDialogsEnabled(
             BOOL *areDefaultScriptDialogsEnabled) = 0;

        virtual  HRESULT STDMETHODCALLTYPE put_AreDefaultScriptDialogsEnabled(
             BOOL areDefaultScriptDialogsEnabled) = 0;

        virtual  HRESULT STDMETHODCALLTYPE get_IsStatusBarEnabled(
             BOOL *isStatusBarEnabled) = 0;

        virtual  HRESULT STDMETHODCALLTYPE put_IsStatusBarEnabled(
             BOOL isStatusBarEnabled) = 0;

        virtual  HRESULT STDMETHODCALLTYPE get_AreDevToolsEnabled(
             BOOL *areDevToolsEnabled) = 0;

        virtual  HRESULT STDMETHODCALLTYPE put_AreDevToolsEnabled(
             BOOL areDevToolsEnabled) = 0;

        virtual  HRESULT STDMETHODCALLTYPE get_AreDefaultContextMenusEnabled(
             BOOL *enabled) = 0;

        virtual  HRESULT STDMETHODCALLTYPE put_AreDefaultContextMenusEnabled(
             BOOL enabled) = 0;

        virtual  HRESULT STDMETHODCALLTYPE get_AreHostObjectsAllowed(
             BOOL *allowed) = 0;

        virtual  HRESULT STDMETHODCALLTYPE put_AreHostObjectsAllowed(
             BOOL allowed) = 0;

        virtual  HRESULT STDMETHODCALLTYPE get_IsZoomControlEnabled(
             BOOL *enabled) = 0;

        virtual  HRESULT STDMETHODCALLTYPE put_IsZoomControlEnabled(
             BOOL enabled) = 0;

        virtual  HRESULT STDMETHODCALLTYPE get_IsBuiltInErrorPageEnabled(
             BOOL *enabled) = 0;

        virtual  HRESULT STDMETHODCALLTYPE put_IsBuiltInErrorPageEnabled(
             BOOL enabled) = 0;

    };

MIDL_INTERFACE("76eceacb-0462-4d94-ac83-423a6793775e")
    ICoreWebView2 : public IUnknown
    {
    public:
        virtual  HRESULT STDMETHODCALLTYPE get_Settings(
             ICoreWebView2Settings **settings) = 0;

        virtual  HRESULT STDMETHODCALLTYPE get_Source(
             LPWSTR *uri) = 0;

        virtual HRESULT STDMETHODCALLTYPE Navigate(
             LPCWSTR uri) = 0;

        virtual HRESULT STDMETHODCALLTYPE NavigateToString(
             LPCWSTR htmlContent) = 0;

        virtual HRESULT STDMETHODCALLTYPE add_NavigationStarting(
             ICoreWebView2NavigationStartingEventHandler *eventHandler,
             EventRegistrationToken *token) = 0;

        virtual HRESULT STDMETHODCALLTYPE remove_NavigationStarting(
             EventRegistrationToken token) = 0;

        virtual HRESULT STDMETHODCALLTYPE add_ContentLoading(
             ICoreWebView2ContentLoadingEventHandler *eventHandler,
             EventRegistrationToken *token) = 0;

        virtual HRESULT STDMETHODCALLTYPE remove_ContentLoading(
             EventRegistrationToken token) = 0;

        virtual HRESULT STDMETHODCALLTYPE add_SourceChanged(
             ICoreWebView2SourceChangedEventHandler *eventHandler,
             EventRegistrationToken *token) = 0;

        virtual HRESULT STDMETHODCALLTYPE remove_SourceChanged(
             EventRegistrationToken token) = 0;

        virtual HRESULT STDMETHODCALLTYPE add_HistoryChanged(
             ICoreWebView2HistoryChangedEventHandler *eventHandler,
             EventRegistrationToken *token) = 0;

        virtual HRESULT STDMETHODCALLTYPE remove_HistoryChanged(
             EventRegistrationToken token) = 0;

        virtual HRESULT STDMETHODCALLTYPE add_NavigationCompleted(
             ICoreWebView2NavigationCompletedEventHandler *eventHandler,
             EventRegistrationToken *token) = 0;

        virtual HRESULT STDMETHODCALLTYPE remove_NavigationCompleted(
             EventRegistrationToken token) = 0;

        virtual HRESULT STDMETHODCALLTYPE add_FrameNavigationStarting(
             ICoreWebView2NavigationStartingEventHandler *eventHandler,
             EventRegistrationToken *token) = 0;

        virtual HRESULT STDMETHODCALLTYPE remove_FrameNavigationStarting(
             EventRegistrationToken token) = 0;

        virtual HRESULT STDMETHODCALLTYPE add_FrameNavigationCompleted(
             ICoreWebView2NavigationCompletedEventHandler *eventHandler,
             EventRegistrationToken *token) = 0;

        virtual HRESULT STDMETHODCALLTYPE remove_FrameNavigationCompleted(
             EventRegistrationToken token) = 0;

        virtual HRESULT STDMETHODCALLTYPE add_ScriptDialogOpening(
             ICoreWebView2ScriptDialogOpeningEventHandler *eventHandler,
             EventRegistrationToken *token) = 0;

        virtual HRESULT STDMETHODCALLTYPE remove_ScriptDialogOpening(
             EventRegistrationToken token) = 0;

        virtual HRESULT STDMETHODCALLTYPE add_PermissionRequested(
             ICoreWebView2PermissionRequestedEventHandler *eventHandler,
             EventRegistrationToken *token) = 0;

        virtual HRESULT STDMETHODCALLTYPE remove_PermissionRequested(
             EventRegistrationToken token) = 0;

        virtual HRESULT STDMETHODCALLTYPE add_ProcessFailed(
             ICoreWebView2ProcessFailedEventHandler *eventHandler,
             EventRegistrationToken *token) = 0;

        virtual HRESULT STDMETHODCALLTYPE remove_ProcessFailed(
             EventRegistrationToken token) = 0;

        virtual HRESULT STDMETHODCALLTYPE AddScriptToExecuteOnDocumentCreated(
             LPCWSTR javaScript,
             ICoreWebView2AddScriptToExecuteOnDocumentCreatedCompletedHandler *handler) = 0;

        virtual HRESULT STDMETHODCALLTYPE RemoveScriptToExecuteOnDocumentCreated(
             LPCWSTR id) = 0;

        virtual HRESULT STDMETHODCALLTYPE ExecuteScript(
             LPCWSTR javaScript,
             ICoreWebView2ExecuteScriptCompletedHandler *handler) = 0;

        virtual HRESULT STDMETHODCALLTYPE CapturePreview(
             COREWEBVIEW2_CAPTURE_PREVIEW_IMAGE_FORMAT imageFormat,
             IStream *imageStream,
             ICoreWebView2CapturePreviewCompletedHandler *handler) = 0;

        virtual HRESULT STDMETHODCALLTYPE Reload( void) = 0;

        virtual HRESULT STDMETHODCALLTYPE PostWebMessageAsJson(
             LPCWSTR webMessageAsJson) = 0;

        virtual HRESULT STDMETHODCALLTYPE PostWebMessageAsString(
             LPCWSTR webMessageAsString) = 0;

        virtual HRESULT STDMETHODCALLTYPE add_WebMessageReceived(
             ICoreWebView2WebMessageReceivedEventHandler *handler,
             EventRegistrationToken *token) = 0;

        virtual HRESULT STDMETHODCALLTYPE remove_WebMessageReceived(
             EventRegistrationToken token) = 0;

        virtual HRESULT STDMETHODCALLTYPE CallDevToolsProtocolMethod(
             LPCWSTR methodName,
             LPCWSTR parametersAsJson,
             ICoreWebView2CallDevToolsProtocolMethodCompletedHandler *handler) = 0;

        virtual  HRESULT STDMETHODCALLTYPE get_BrowserProcessId(
             UINT32 *value) = 0;

        virtual  HRESULT STDMETHODCALLTYPE get_CanGoBack(
             BOOL *canGoBack) = 0;

        virtual  HRESULT STDMETHODCALLTYPE get_CanGoForward(
             BOOL *canGoForward) = 0;

        virtual HRESULT STDMETHODCALLTYPE GoBack( void) = 0;

        virtual HRESULT STDMETHODCALLTYPE GoForward( void) = 0;

        virtual HRESULT STDMETHODCALLTYPE GetDevToolsProtocolEventReceiver(
             LPCWSTR eventName,
             ICoreWebView2DevToolsProtocolEventReceiver **receiver) = 0;

        virtual HRESULT STDMETHODCALLTYPE Stop( void) = 0;

        virtual HRESULT STDMETHODCALLTYPE add_NewWindowRequested(
             ICoreWebView2NewWindowRequestedEventHandler *eventHandler,
             EventRegistrationToken *token) = 0;

        virtual HRESULT STDMETHODCALLTYPE remove_NewWindowRequested(
             EventRegistrationToken token) = 0;

        virtual HRESULT STDMETHODCALLTYPE add_DocumentTitleChanged(
             ICoreWebView2DocumentTitleChangedEventHandler *eventHandler,
             EventRegistrationToken *token) = 0;

        virtual HRESULT STDMETHODCALLTYPE remove_DocumentTitleChanged(
             EventRegistrationToken token) = 0;

        virtual  HRESULT STDMETHODCALLTYPE get_DocumentTitle(
             LPWSTR *title) = 0;

        virtual HRESULT STDMETHODCALLTYPE AddHostObjectToScript(
             LPCWSTR name,
             VARIANT *object) = 0;

        virtual HRESULT STDMETHODCALLTYPE RemoveHostObjectFromScript(
             LPCWSTR name) = 0;

        virtual HRESULT STDMETHODCALLTYPE OpenDevToolsWindow( void) = 0;

        virtual HRESULT STDMETHODCALLTYPE add_ContainsFullScreenElementChanged(
             ICoreWebView2ContainsFullScreenElementChangedEventHandler *eventHandler,
             EventRegistrationToken *token) = 0;

        virtual HRESULT STDMETHODCALLTYPE remove_ContainsFullScreenElementChanged(
             EventRegistrationToken token) = 0;

        virtual  HRESULT STDMETHODCALLTYPE get_ContainsFullScreenElement(
             BOOL *containsFullScreenElement) = 0;

        virtual HRESULT STDMETHODCALLTYPE add_WebResourceRequested(
             ICoreWebView2WebResourceRequestedEventHandler *eventHandler,
             EventRegistrationToken *token) = 0;

        virtual HRESULT STDMETHODCALLTYPE remove_WebResourceRequested(
             EventRegistrationToken token) = 0;

        virtual HRESULT STDMETHODCALLTYPE AddWebResourceRequestedFilter(
             const LPCWSTR uri,
             const COREWEBVIEW2_WEB_RESOURCE_CONTEXT resourceContext) = 0;

        virtual HRESULT STDMETHODCALLTYPE RemoveWebResourceRequestedFilter(
             const LPCWSTR uri,
             const COREWEBVIEW2_WEB_RESOURCE_CONTEXT resourceContext) = 0;

        virtual HRESULT STDMETHODCALLTYPE add_WindowCloseRequested(
             ICoreWebView2WindowCloseRequestedEventHandler *eventHandler,
             EventRegistrationToken *token) = 0;

        virtual HRESULT STDMETHODCALLTYPE remove_WindowCloseRequested(
             EventRegistrationToken token) = 0;

    };

MIDL_INTERFACE("4e8a3389-c9d8-4bd2-b6b5-124fee6cc14d")
    ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE Invoke(
             HRESULT errorCode,
             ICoreWebView2Environment *result) = 0;

    };

MIDL_INTERFACE("6c4819f3-c9b7-4260-8127-c9f5bde7f68c")
    ICoreWebView2CreateCoreWebView2ControllerCompletedHandler : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE Invoke(
             HRESULT errorCode,
             ICoreWebView2Controller *result) = 0;

    };

MIDL_INTERFACE("34acb11c-fc37-4418-9132-f9c21d1eafb9")
    ICoreWebView2NewWindowRequestedEventArgs : public IUnknown
    {
    public:
        virtual  HRESULT STDMETHODCALLTYPE get_Uri(
             LPWSTR *uri) = 0;

        virtual  HRESULT STDMETHODCALLTYPE put_NewWindow(
             ICoreWebView2 *newWindow) = 0;

        virtual  HRESULT STDMETHODCALLTYPE get_NewWindow(
             ICoreWebView2 **newWindow) = 0;

        virtual  HRESULT STDMETHODCALLTYPE put_Handled(
             BOOL handled) = 0;

        virtual  HRESULT STDMETHODCALLTYPE get_Handled(
             BOOL *handled) = 0;

        virtual  HRESULT STDMETHODCALLTYPE get_IsUserInitiated(
             BOOL *isUserInitiated) = 0;

        virtual HRESULT STDMETHODCALLTYPE GetDeferral(
             ICoreWebView2Deferral **deferral) = 0;

        virtual  HRESULT STDMETHODCALLTYPE get_WindowFeatures(
             ICoreWebView2WindowFeatures **value) = 0;

    };

MIDL_INTERFACE("d4c185fe-c81c-4989-97af-2d3fa7ab5651")
    ICoreWebView2NewWindowRequestedEventHandler : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE Invoke(
             ICoreWebView2 *sender,
             ICoreWebView2NewWindowRequestedEventArgs *args) = 0;

    };

MIDL_INTERFACE("2fde08a8-1e9a-4766-8c05-95a9ceb9d1c5")
    ICoreWebView2EnvironmentOptions : public IUnknown
    {
    public:
        virtual  HRESULT STDMETHODCALLTYPE get_AdditionalBrowserArguments(
             LPWSTR *value) = 0;

        virtual  HRESULT STDMETHODCALLTYPE put_AdditionalBrowserArguments(
             LPCWSTR value) = 0;

        virtual  HRESULT STDMETHODCALLTYPE get_Language(
             LPWSTR *value) = 0;

        virtual  HRESULT STDMETHODCALLTYPE put_Language(
             LPCWSTR value) = 0;

        virtual  HRESULT STDMETHODCALLTYPE get_TargetCompatibleBrowserVersion(
             LPWSTR *value) = 0;

        virtual  HRESULT STDMETHODCALLTYPE put_TargetCompatibleBrowserVersion(
             LPCWSTR value) = 0;

        virtual  HRESULT STDMETHODCALLTYPE get_AllowSingleSignOnUsingOSPrimaryAccount(
             BOOL *allow) = 0;

        virtual  HRESULT STDMETHODCALLTYPE put_AllowSingleSignOnUsingOSPrimaryAccount(
             BOOL allow) = 0;

    };

#endif
