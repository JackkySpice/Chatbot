.class public final Landroidx/appcompat/view/menu/hc0$a$a;
.super Landroidx/appcompat/view/menu/hy0;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/xw;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Landroidx/appcompat/view/menu/hc0$a;->e(Landroidx/appcompat/view/menu/gl;)Landroidx/appcompat/view/menu/g90;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation


# instance fields
.field public q:I

.field public final synthetic r:Landroidx/appcompat/view/menu/hc0$a;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/hc0$a;Landroidx/appcompat/view/menu/gl;Landroidx/appcompat/view/menu/wg;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/hc0$a$a;->r:Landroidx/appcompat/view/menu/hc0$a;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Landroidx/appcompat/view/menu/hy0;-><init>(ILandroidx/appcompat/view/menu/wg;)V

    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Landroidx/appcompat/view/menu/wg;)Landroidx/appcompat/view/menu/wg;
    .locals 2

    new-instance p1, Landroidx/appcompat/view/menu/hc0$a$a;

    iget-object v0, p0, Landroidx/appcompat/view/menu/hc0$a$a;->r:Landroidx/appcompat/view/menu/hc0$a;

    const/4 v1, 0x0

    invoke-direct {p1, v0, v1, p2}, Landroidx/appcompat/view/menu/hc0$a$a;-><init>(Landroidx/appcompat/view/menu/hc0$a;Landroidx/appcompat/view/menu/gl;Landroidx/appcompat/view/menu/wg;)V

    return-object p1
.end method

.method public bridge synthetic h(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Landroidx/appcompat/view/menu/sh;

    check-cast p2, Landroidx/appcompat/view/menu/wg;

    invoke-virtual {p0, p1, p2}, Landroidx/appcompat/view/menu/hc0$a$a;->o(Landroidx/appcompat/view/menu/sh;Landroidx/appcompat/view/menu/wg;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final k(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    invoke-static {}, Landroidx/appcompat/view/menu/y50;->c()Ljava/lang/Object;

    move-result-object v0

    iget v1, p0, Landroidx/appcompat/view/menu/hc0$a$a;->q:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Landroidx/appcompat/view/menu/kp0;->b(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Landroidx/appcompat/view/menu/kp0;->b(Ljava/lang/Object;)V

    iget-object p1, p0, Landroidx/appcompat/view/menu/hc0$a$a;->r:Landroidx/appcompat/view/menu/hc0$a;

    invoke-static {p1}, Landroidx/appcompat/view/menu/hc0$a;->d(Landroidx/appcompat/view/menu/hc0$a;)Landroidx/appcompat/view/menu/gc0;

    move-result-object p1

    iput v2, p0, Landroidx/appcompat/view/menu/hc0$a$a;->q:I

    const/4 v1, 0x0

    invoke-virtual {p1, v1, p0}, Landroidx/appcompat/view/menu/gc0;->a(Landroidx/appcompat/view/menu/gl;Landroidx/appcompat/view/menu/wg;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Landroidx/appcompat/view/menu/n31;->a:Landroidx/appcompat/view/menu/n31;

    return-object p1
.end method

.method public final o(Landroidx/appcompat/view/menu/sh;Landroidx/appcompat/view/menu/wg;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p0, p1, p2}, Landroidx/appcompat/view/menu/hc0$a$a;->a(Ljava/lang/Object;Landroidx/appcompat/view/menu/wg;)Landroidx/appcompat/view/menu/wg;

    move-result-object p1

    check-cast p1, Landroidx/appcompat/view/menu/hc0$a$a;

    sget-object p2, Landroidx/appcompat/view/menu/n31;->a:Landroidx/appcompat/view/menu/n31;

    invoke-virtual {p1, p2}, Landroidx/appcompat/view/menu/hc0$a$a;->k(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
