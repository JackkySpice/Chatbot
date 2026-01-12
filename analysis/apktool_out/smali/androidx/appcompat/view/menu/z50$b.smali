.class public final Landroidx/appcompat/view/menu/z50$b;
.super Landroidx/appcompat/view/menu/yg;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Landroidx/appcompat/view/menu/z50;->a(Landroidx/appcompat/view/menu/xw;Ljava/lang/Object;Landroidx/appcompat/view/menu/wg;)Landroidx/appcompat/view/menu/wg;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation


# instance fields
.field public p:I

.field public final synthetic q:Landroidx/appcompat/view/menu/xw;

.field public final synthetic r:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/wg;Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/xw;Ljava/lang/Object;)V
    .locals 0

    iput-object p3, p0, Landroidx/appcompat/view/menu/z50$b;->q:Landroidx/appcompat/view/menu/xw;

    iput-object p4, p0, Landroidx/appcompat/view/menu/z50$b;->r:Ljava/lang/Object;

    const-string p3, "null cannot be cast to non-null type kotlin.coroutines.Continuation<kotlin.Any?>"

    invoke-static {p1, p3}, Landroidx/appcompat/view/menu/x50;->c(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0, p1, p2}, Landroidx/appcompat/view/menu/yg;-><init>(Landroidx/appcompat/view/menu/wg;Landroidx/appcompat/view/menu/jh;)V

    return-void
.end method


# virtual methods
.method public k(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    iget v0, p0, Landroidx/appcompat/view/menu/z50$b;->p:I

    const/4 v1, 0x2

    const/4 v2, 0x1

    if-eqz v0, :cond_1

    if-ne v0, v2, :cond_0

    iput v1, p0, Landroidx/appcompat/view/menu/z50$b;->p:I

    invoke-static {p1}, Landroidx/appcompat/view/menu/kp0;->b(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "This coroutine had already completed"

    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    iput v2, p0, Landroidx/appcompat/view/menu/z50$b;->p:I

    invoke-static {p1}, Landroidx/appcompat/view/menu/kp0;->b(Ljava/lang/Object;)V

    iget-object p1, p0, Landroidx/appcompat/view/menu/z50$b;->q:Landroidx/appcompat/view/menu/xw;

    const-string v0, "null cannot be cast to non-null type kotlin.Function2<R of kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsJvmKt.createCoroutineUnintercepted$lambda$1, kotlin.coroutines.Continuation<T of kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsJvmKt.createCoroutineUnintercepted$lambda$1>, kotlin.Any?>"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->c(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p0, Landroidx/appcompat/view/menu/z50$b;->q:Landroidx/appcompat/view/menu/xw;

    invoke-static {p1, v1}, Landroidx/appcompat/view/menu/m21;->a(Ljava/lang/Object;I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroidx/appcompat/view/menu/xw;

    iget-object v0, p0, Landroidx/appcompat/view/menu/z50$b;->r:Ljava/lang/Object;

    invoke-interface {p1, v0, p0}, Landroidx/appcompat/view/menu/xw;->h(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    :goto_0
    return-object p1
.end method
