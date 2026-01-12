.class public abstract Landroidx/appcompat/view/menu/aa;
.super Ljava/lang/Object;
.source "SourceFile"


# direct methods
.method public static final a(Landroidx/appcompat/view/menu/wg;Ljava/lang/Throwable;)V
    .locals 1

    sget-object v0, Landroidx/appcompat/view/menu/jp0;->m:Landroidx/appcompat/view/menu/jp0$a;

    invoke-static {p1}, Landroidx/appcompat/view/menu/kp0;->a(Ljava/lang/Throwable;)Ljava/lang/Object;

    move-result-object v0

    invoke-static {v0}, Landroidx/appcompat/view/menu/jp0;->a(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    invoke-interface {p0, v0}, Landroidx/appcompat/view/menu/wg;->n(Ljava/lang/Object;)V

    throw p1
.end method

.method public static final b(Landroidx/appcompat/view/menu/wg;Landroidx/appcompat/view/menu/wg;)V
    .locals 3

    :try_start_0
    invoke-static {p0}, Landroidx/appcompat/view/menu/y50;->b(Landroidx/appcompat/view/menu/wg;)Landroidx/appcompat/view/menu/wg;

    move-result-object p0

    sget-object v0, Landroidx/appcompat/view/menu/jp0;->m:Landroidx/appcompat/view/menu/jp0$a;

    sget-object v0, Landroidx/appcompat/view/menu/n31;->a:Landroidx/appcompat/view/menu/n31;

    invoke-static {v0}, Landroidx/appcompat/view/menu/jp0;->a(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    const/4 v1, 0x2

    const/4 v2, 0x0

    invoke-static {p0, v0, v2, v1, v2}, Landroidx/appcompat/view/menu/bm;->c(Landroidx/appcompat/view/menu/wg;Ljava/lang/Object;Landroidx/appcompat/view/menu/jw;ILjava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p0

    invoke-static {p1, p0}, Landroidx/appcompat/view/menu/aa;->a(Landroidx/appcompat/view/menu/wg;Ljava/lang/Throwable;)V

    :goto_0
    return-void
.end method

.method public static final c(Landroidx/appcompat/view/menu/xw;Ljava/lang/Object;Landroidx/appcompat/view/menu/wg;Landroidx/appcompat/view/menu/jw;)V
    .locals 0

    :try_start_0
    invoke-static {p0, p1, p2}, Landroidx/appcompat/view/menu/y50;->a(Landroidx/appcompat/view/menu/xw;Ljava/lang/Object;Landroidx/appcompat/view/menu/wg;)Landroidx/appcompat/view/menu/wg;

    move-result-object p0

    invoke-static {p0}, Landroidx/appcompat/view/menu/y50;->b(Landroidx/appcompat/view/menu/wg;)Landroidx/appcompat/view/menu/wg;

    move-result-object p0

    sget-object p1, Landroidx/appcompat/view/menu/jp0;->m:Landroidx/appcompat/view/menu/jp0$a;

    sget-object p1, Landroidx/appcompat/view/menu/n31;->a:Landroidx/appcompat/view/menu/n31;

    invoke-static {p1}, Landroidx/appcompat/view/menu/jp0;->a(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    invoke-static {p0, p1, p3}, Landroidx/appcompat/view/menu/bm;->b(Landroidx/appcompat/view/menu/wg;Ljava/lang/Object;Landroidx/appcompat/view/menu/jw;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p0

    invoke-static {p2, p0}, Landroidx/appcompat/view/menu/aa;->a(Landroidx/appcompat/view/menu/wg;Ljava/lang/Throwable;)V

    :goto_0
    return-void
.end method

.method public static synthetic d(Landroidx/appcompat/view/menu/xw;Ljava/lang/Object;Landroidx/appcompat/view/menu/wg;Landroidx/appcompat/view/menu/jw;ILjava/lang/Object;)V
    .locals 0

    and-int/lit8 p4, p4, 0x4

    if-eqz p4, :cond_0

    const/4 p3, 0x0

    :cond_0
    invoke-static {p0, p1, p2, p3}, Landroidx/appcompat/view/menu/aa;->c(Landroidx/appcompat/view/menu/xw;Ljava/lang/Object;Landroidx/appcompat/view/menu/wg;Landroidx/appcompat/view/menu/jw;)V

    return-void
.end method
