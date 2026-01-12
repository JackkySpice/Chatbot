.class public Landroidx/appcompat/view/menu/ju$b;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/mu;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/ju;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public final synthetic a:Landroidx/appcompat/view/menu/ju;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/ju;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/ju$b;->a:Landroidx/appcompat/view/menu/ju;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public c()V
    .locals 0

    return-void
.end method

.method public f()V
    .locals 2

    const-string v0, "FlutterSurfaceView"

    const-string v1, "onFlutterUiDisplayed()"

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/ba0;->f(Ljava/lang/String;Ljava/lang/String;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/ju$b;->a:Landroidx/appcompat/view/menu/ju;

    const/high16 v1, 0x3f800000    # 1.0f

    invoke-virtual {v0, v1}, Landroid/view/View;->setAlpha(F)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/ju$b;->a:Landroidx/appcompat/view/menu/ju;

    invoke-static {v0}, Landroidx/appcompat/view/menu/ju;->j(Landroidx/appcompat/view/menu/ju;)Lio/flutter/embedding/engine/renderer/FlutterRenderer;

    move-result-object v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Landroidx/appcompat/view/menu/ju$b;->a:Landroidx/appcompat/view/menu/ju;

    invoke-static {v0}, Landroidx/appcompat/view/menu/ju;->j(Landroidx/appcompat/view/menu/ju;)Lio/flutter/embedding/engine/renderer/FlutterRenderer;

    move-result-object v0

    invoke-virtual {v0, p0}, Lio/flutter/embedding/engine/renderer/FlutterRenderer;->l(Landroidx/appcompat/view/menu/mu;)V

    :cond_0
    return-void
.end method
