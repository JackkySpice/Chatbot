.class public final Landroidx/appcompat/view/menu/g81$a;
.super Landroidx/appcompat/view/menu/hy0;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/xw;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Landroidx/appcompat/view/menu/g81;->a(Landroid/app/Activity;)Landroidx/appcompat/view/menu/ws;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation


# instance fields
.field public q:I

.field public synthetic r:Ljava/lang/Object;

.field public final synthetic s:Landroidx/appcompat/view/menu/g81;

.field public final synthetic t:Landroid/app/Activity;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/g81;Landroid/app/Activity;Landroidx/appcompat/view/menu/wg;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/g81$a;->s:Landroidx/appcompat/view/menu/g81;

    iput-object p2, p0, Landroidx/appcompat/view/menu/g81$a;->t:Landroid/app/Activity;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Landroidx/appcompat/view/menu/hy0;-><init>(ILandroidx/appcompat/view/menu/wg;)V

    return-void
.end method

.method public static synthetic o(Landroidx/appcompat/view/menu/ck0;Landroidx/appcompat/view/menu/u91;)V
    .locals 0

    invoke-static {p0, p1}, Landroidx/appcompat/view/menu/g81$a;->q(Landroidx/appcompat/view/menu/ck0;Landroidx/appcompat/view/menu/u91;)V

    return-void
.end method

.method public static final q(Landroidx/appcompat/view/menu/ck0;Landroidx/appcompat/view/menu/u91;)V
    .locals 0

    invoke-interface {p0, p1}, Landroidx/appcompat/view/menu/hs0;->y(Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Landroidx/appcompat/view/menu/wg;)Landroidx/appcompat/view/menu/wg;
    .locals 3

    new-instance v0, Landroidx/appcompat/view/menu/g81$a;

    iget-object v1, p0, Landroidx/appcompat/view/menu/g81$a;->s:Landroidx/appcompat/view/menu/g81;

    iget-object v2, p0, Landroidx/appcompat/view/menu/g81$a;->t:Landroid/app/Activity;

    invoke-direct {v0, v1, v2, p2}, Landroidx/appcompat/view/menu/g81$a;-><init>(Landroidx/appcompat/view/menu/g81;Landroid/app/Activity;Landroidx/appcompat/view/menu/wg;)V

    iput-object p1, v0, Landroidx/appcompat/view/menu/g81$a;->r:Ljava/lang/Object;

    return-object v0
.end method

.method public bridge synthetic h(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Landroidx/appcompat/view/menu/ck0;

    check-cast p2, Landroidx/appcompat/view/menu/wg;

    invoke-virtual {p0, p1, p2}, Landroidx/appcompat/view/menu/g81$a;->p(Landroidx/appcompat/view/menu/ck0;Landroidx/appcompat/view/menu/wg;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final k(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    invoke-static {}, Landroidx/appcompat/view/menu/y50;->c()Ljava/lang/Object;

    move-result-object v0

    iget v1, p0, Landroidx/appcompat/view/menu/g81$a;->q:I

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

    iget-object p1, p0, Landroidx/appcompat/view/menu/g81$a;->r:Ljava/lang/Object;

    check-cast p1, Landroidx/appcompat/view/menu/ck0;

    new-instance v1, Landroidx/appcompat/view/menu/f81;

    invoke-direct {v1, p1}, Landroidx/appcompat/view/menu/f81;-><init>(Landroidx/appcompat/view/menu/ck0;)V

    iget-object v3, p0, Landroidx/appcompat/view/menu/g81$a;->s:Landroidx/appcompat/view/menu/g81;

    invoke-static {v3}, Landroidx/appcompat/view/menu/g81;->b(Landroidx/appcompat/view/menu/g81;)Landroidx/appcompat/view/menu/x71;

    move-result-object v3

    iget-object v4, p0, Landroidx/appcompat/view/menu/g81$a;->t:Landroid/app/Activity;

    new-instance v5, Landroidx/appcompat/view/menu/fc0;

    invoke-direct {v5}, Landroidx/appcompat/view/menu/fc0;-><init>()V

    invoke-interface {v3, v4, v5, v1}, Landroidx/appcompat/view/menu/x71;->a(Landroid/content/Context;Ljava/util/concurrent/Executor;Landroidx/appcompat/view/menu/of;)V

    new-instance v3, Landroidx/appcompat/view/menu/g81$a$a;

    iget-object v4, p0, Landroidx/appcompat/view/menu/g81$a;->s:Landroidx/appcompat/view/menu/g81;

    invoke-direct {v3, v4, v1}, Landroidx/appcompat/view/menu/g81$a$a;-><init>(Landroidx/appcompat/view/menu/g81;Landroidx/appcompat/view/menu/of;)V

    iput v2, p0, Landroidx/appcompat/view/menu/g81$a;->q:I

    invoke-static {p1, v3, p0}, Landroidx/appcompat/view/menu/ak0;->a(Landroidx/appcompat/view/menu/ck0;Landroidx/appcompat/view/menu/hw;Landroidx/appcompat/view/menu/wg;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Landroidx/appcompat/view/menu/n31;->a:Landroidx/appcompat/view/menu/n31;

    return-object p1
.end method

.method public final p(Landroidx/appcompat/view/menu/ck0;Landroidx/appcompat/view/menu/wg;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p0, p1, p2}, Landroidx/appcompat/view/menu/g81$a;->a(Ljava/lang/Object;Landroidx/appcompat/view/menu/wg;)Landroidx/appcompat/view/menu/wg;

    move-result-object p1

    check-cast p1, Landroidx/appcompat/view/menu/g81$a;

    sget-object p2, Landroidx/appcompat/view/menu/n31;->a:Landroidx/appcompat/view/menu/n31;

    invoke-virtual {p1, p2}, Landroidx/appcompat/view/menu/g81$a;->k(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
