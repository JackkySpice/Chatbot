.class public final synthetic Landroidx/appcompat/view/menu/b02;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public synthetic m:Landroidx/appcompat/view/menu/zz1;

.field public synthetic n:Ljava/util/concurrent/atomic/AtomicReference;


# direct methods
.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/zz1;Ljava/util/concurrent/atomic/AtomicReference;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/b02;->m:Landroidx/appcompat/view/menu/zz1;

    iput-object p2, p0, Landroidx/appcompat/view/menu/b02;->n:Ljava/util/concurrent/atomic/AtomicReference;

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 3

    iget-object v0, p0, Landroidx/appcompat/view/menu/b02;->m:Landroidx/appcompat/view/menu/zz1;

    iget-object v1, p0, Landroidx/appcompat/view/menu/b02;->n:Ljava/util/concurrent/atomic/AtomicReference;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/bz1;->i()Landroidx/appcompat/view/menu/pu1;

    move-result-object v2

    iget-object v2, v2, Landroidx/appcompat/view/menu/pu1;->n:Landroidx/appcompat/view/menu/tu1;

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/tu1;->a()Landroid/os/Bundle;

    move-result-object v2

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/dr1;->t()Landroidx/appcompat/view/menu/d42;

    move-result-object v0

    if-nez v2, :cond_0

    new-instance v2, Landroid/os/Bundle;

    invoke-direct {v2}, Landroid/os/Bundle;-><init>()V

    :cond_0
    invoke-virtual {v0, v1, v2}, Landroidx/appcompat/view/menu/d42;->R(Ljava/util/concurrent/atomic/AtomicReference;Landroid/os/Bundle;)V

    return-void
.end method
