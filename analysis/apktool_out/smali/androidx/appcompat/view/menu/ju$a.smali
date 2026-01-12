.class public Landroidx/appcompat/view/menu/ju$a;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/view/SurfaceHolder$Callback;


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

    iput-object p1, p0, Landroidx/appcompat/view/menu/ju$a;->a:Landroidx/appcompat/view/menu/ju;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public surfaceChanged(Landroid/view/SurfaceHolder;III)V
    .locals 0

    const-string p1, "FlutterSurfaceView"

    const-string p2, "SurfaceHolder.Callback.surfaceChanged()"

    invoke-static {p1, p2}, Landroidx/appcompat/view/menu/ba0;->f(Ljava/lang/String;Ljava/lang/String;)V

    iget-object p1, p0, Landroidx/appcompat/view/menu/ju$a;->a:Landroidx/appcompat/view/menu/ju;

    invoke-static {p1}, Landroidx/appcompat/view/menu/ju;->f(Landroidx/appcompat/view/menu/ju;)Z

    move-result p1

    if-eqz p1, :cond_0

    iget-object p1, p0, Landroidx/appcompat/view/menu/ju$a;->a:Landroidx/appcompat/view/menu/ju;

    invoke-static {p1, p3, p4}, Landroidx/appcompat/view/menu/ju;->h(Landroidx/appcompat/view/menu/ju;II)V

    :cond_0
    return-void
.end method

.method public surfaceCreated(Landroid/view/SurfaceHolder;)V
    .locals 1

    const-string p1, "FlutterSurfaceView"

    const-string v0, "SurfaceHolder.Callback.startRenderingToSurface()"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/ba0;->f(Ljava/lang/String;Ljava/lang/String;)V

    iget-object p1, p0, Landroidx/appcompat/view/menu/ju$a;->a:Landroidx/appcompat/view/menu/ju;

    const/4 v0, 0x1

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/ju;->e(Landroidx/appcompat/view/menu/ju;Z)Z

    iget-object p1, p0, Landroidx/appcompat/view/menu/ju$a;->a:Landroidx/appcompat/view/menu/ju;

    invoke-static {p1}, Landroidx/appcompat/view/menu/ju;->f(Landroidx/appcompat/view/menu/ju;)Z

    move-result p1

    if-eqz p1, :cond_0

    iget-object p1, p0, Landroidx/appcompat/view/menu/ju$a;->a:Landroidx/appcompat/view/menu/ju;

    invoke-static {p1}, Landroidx/appcompat/view/menu/ju;->g(Landroidx/appcompat/view/menu/ju;)V

    :cond_0
    return-void
.end method

.method public surfaceDestroyed(Landroid/view/SurfaceHolder;)V
    .locals 1

    const-string p1, "FlutterSurfaceView"

    const-string v0, "SurfaceHolder.Callback.stopRenderingToSurface()"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/ba0;->f(Ljava/lang/String;Ljava/lang/String;)V

    iget-object p1, p0, Landroidx/appcompat/view/menu/ju$a;->a:Landroidx/appcompat/view/menu/ju;

    const/4 v0, 0x0

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/ju;->e(Landroidx/appcompat/view/menu/ju;Z)Z

    iget-object p1, p0, Landroidx/appcompat/view/menu/ju$a;->a:Landroidx/appcompat/view/menu/ju;

    invoke-static {p1}, Landroidx/appcompat/view/menu/ju;->f(Landroidx/appcompat/view/menu/ju;)Z

    move-result p1

    if-eqz p1, :cond_0

    iget-object p1, p0, Landroidx/appcompat/view/menu/ju$a;->a:Landroidx/appcompat/view/menu/ju;

    invoke-static {p1}, Landroidx/appcompat/view/menu/ju;->i(Landroidx/appcompat/view/menu/ju;)V

    :cond_0
    return-void
.end method
