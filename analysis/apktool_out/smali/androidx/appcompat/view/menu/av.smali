.class public abstract Landroidx/appcompat/view/menu/av;
.super Ljava/lang/Object;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroidx/appcompat/view/menu/av$b;,
        Landroidx/appcompat/view/menu/av$a;,
        Landroidx/appcompat/view/menu/av$c;
    }
.end annotation


# direct methods
.method public static a(Landroid/content/Context;Landroid/os/CancellationSignal;[Landroidx/appcompat/view/menu/av$b;)Landroid/graphics/Typeface;
    .locals 1

    const/4 v0, 0x0

    invoke-static {p0, p1, p2, v0}, Landroidx/appcompat/view/menu/o21;->b(Landroid/content/Context;Landroid/os/CancellationSignal;[Landroidx/appcompat/view/menu/av$b;I)Landroid/graphics/Typeface;

    move-result-object p0

    return-object p0
.end method

.method public static b(Landroid/content/Context;Landroid/os/CancellationSignal;Landroidx/appcompat/view/menu/wu;)Landroidx/appcompat/view/menu/av$a;
    .locals 0

    invoke-static {p0, p2, p1}, Landroidx/appcompat/view/menu/vu;->e(Landroid/content/Context;Landroidx/appcompat/view/menu/wu;Landroid/os/CancellationSignal;)Landroidx/appcompat/view/menu/av$a;

    move-result-object p0

    return-object p0
.end method

.method public static c(Landroid/content/Context;Landroidx/appcompat/view/menu/wu;IZILandroid/os/Handler;Landroidx/appcompat/view/menu/av$c;)Landroid/graphics/Typeface;
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/o9;

    invoke-direct {v0, p6, p5}, Landroidx/appcompat/view/menu/o9;-><init>(Landroidx/appcompat/view/menu/av$c;Landroid/os/Handler;)V

    if-eqz p3, :cond_0

    invoke-static {p0, p1, v0, p2, p4}, Landroidx/appcompat/view/menu/yu;->e(Landroid/content/Context;Landroidx/appcompat/view/menu/wu;Landroidx/appcompat/view/menu/o9;II)Landroid/graphics/Typeface;

    move-result-object p0

    return-object p0

    :cond_0
    const/4 p3, 0x0

    invoke-static {p0, p1, p2, p3, v0}, Landroidx/appcompat/view/menu/yu;->d(Landroid/content/Context;Landroidx/appcompat/view/menu/wu;ILjava/util/concurrent/Executor;Landroidx/appcompat/view/menu/o9;)Landroid/graphics/Typeface;

    move-result-object p0

    return-object p0
.end method
