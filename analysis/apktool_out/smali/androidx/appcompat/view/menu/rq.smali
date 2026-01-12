.class public final synthetic Landroidx/appcompat/view/menu/rq;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/view/View$OnClickListener;


# instance fields
.field public final synthetic a:Landroid/webkit/CookieManager;

.field public final synthetic b:Landroid/webkit/WebView;

.field public final synthetic c:Landroid/app/Activity;


# direct methods
.method public synthetic constructor <init>(Landroid/webkit/CookieManager;Landroid/webkit/WebView;Landroid/app/Activity;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/rq;->a:Landroid/webkit/CookieManager;

    iput-object p2, p0, Landroidx/appcompat/view/menu/rq;->b:Landroid/webkit/WebView;

    iput-object p3, p0, Landroidx/appcompat/view/menu/rq;->c:Landroid/app/Activity;

    return-void
.end method


# virtual methods
.method public final onClick(Landroid/view/View;)V
    .locals 3

    iget-object v0, p0, Landroidx/appcompat/view/menu/rq;->a:Landroid/webkit/CookieManager;

    iget-object v1, p0, Landroidx/appcompat/view/menu/rq;->b:Landroid/webkit/WebView;

    iget-object v2, p0, Landroidx/appcompat/view/menu/rq;->c:Landroid/app/Activity;

    invoke-static {v0, v1, v2, p1}, Landroidx/appcompat/view/menu/tq;->a(Landroid/webkit/CookieManager;Landroid/webkit/WebView;Landroid/app/Activity;Landroid/view/View;)V

    return-void
.end method
