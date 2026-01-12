.class public abstract Landroidx/appcompat/view/menu/mx;
.super Landroidx/appcompat/view/menu/ny;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroidx/appcompat/view/menu/mx$a;
    }
.end annotation


# direct methods
.method public static a(Landroidx/appcompat/view/menu/g90;Landroidx/appcompat/view/menu/lx;Ljava/util/concurrent/Executor;)V
    .locals 1

    invoke-static {p1}, Landroidx/appcompat/view/menu/jj0;->i(Ljava/lang/Object;)Ljava/lang/Object;

    new-instance v0, Landroidx/appcompat/view/menu/mx$a;

    invoke-direct {v0, p0, p1}, Landroidx/appcompat/view/menu/mx$a;-><init>(Ljava/util/concurrent/Future;Landroidx/appcompat/view/menu/lx;)V

    invoke-interface {p0, v0, p2}, Landroidx/appcompat/view/menu/g90;->c(Ljava/lang/Runnable;Ljava/util/concurrent/Executor;)V

    return-void
.end method

.method public static b(Ljava/util/concurrent/Future;)Ljava/lang/Object;
    .locals 2

    invoke-interface {p0}, Ljava/util/concurrent/Future;->isDone()Z

    move-result v0

    const-string v1, "Future was expected to be done: %s"

    invoke-static {v0, v1, p0}, Landroidx/appcompat/view/menu/jj0;->o(ZLjava/lang/String;Ljava/lang/Object;)V

    invoke-static {p0}, Landroidx/appcompat/view/menu/m31;->a(Ljava/util/concurrent/Future;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method
