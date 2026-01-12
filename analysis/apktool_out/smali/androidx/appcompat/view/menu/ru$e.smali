.class public Landroidx/appcompat/view/menu/ru$e;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/mu;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Landroidx/appcompat/view/menu/ru;->A(Ljava/lang/Runnable;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public final synthetic a:Lio/flutter/embedding/engine/renderer/FlutterRenderer;

.field public final synthetic b:Ljava/lang/Runnable;

.field public final synthetic c:Landroidx/appcompat/view/menu/ru;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/ru;Lio/flutter/embedding/engine/renderer/FlutterRenderer;Ljava/lang/Runnable;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/ru$e;->c:Landroidx/appcompat/view/menu/ru;

    iput-object p2, p0, Landroidx/appcompat/view/menu/ru$e;->a:Lio/flutter/embedding/engine/renderer/FlutterRenderer;

    iput-object p3, p0, Landroidx/appcompat/view/menu/ru$e;->b:Ljava/lang/Runnable;

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

    iget-object v0, p0, Landroidx/appcompat/view/menu/ru$e;->a:Lio/flutter/embedding/engine/renderer/FlutterRenderer;

    invoke-virtual {v0, p0}, Lio/flutter/embedding/engine/renderer/FlutterRenderer;->l(Landroidx/appcompat/view/menu/mu;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/ru$e;->b:Ljava/lang/Runnable;

    invoke-interface {v0}, Ljava/lang/Runnable;->run()V

    iget-object v0, p0, Landroidx/appcompat/view/menu/ru$e;->c:Landroidx/appcompat/view/menu/ru;

    iget-object v1, v0, Landroidx/appcompat/view/menu/ru;->d:Landroidx/appcompat/view/menu/ro0;

    instance-of v1, v1, Landroidx/appcompat/view/menu/st;

    if-nez v1, :cond_0

    invoke-static {v0}, Landroidx/appcompat/view/menu/ru;->i(Landroidx/appcompat/view/menu/ru;)Landroidx/appcompat/view/menu/st;

    move-result-object v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Landroidx/appcompat/view/menu/ru$e;->c:Landroidx/appcompat/view/menu/ru;

    invoke-static {v0}, Landroidx/appcompat/view/menu/ru;->i(Landroidx/appcompat/view/menu/ru;)Landroidx/appcompat/view/menu/st;

    move-result-object v0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/st;->a()V

    iget-object v0, p0, Landroidx/appcompat/view/menu/ru$e;->c:Landroidx/appcompat/view/menu/ru;

    invoke-static {v0}, Landroidx/appcompat/view/menu/ru;->j(Landroidx/appcompat/view/menu/ru;)V

    :cond_0
    return-void
.end method
