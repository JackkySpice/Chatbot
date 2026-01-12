.class public abstract Landroidx/appcompat/view/menu/dm;
.super Ljava/lang/Object;
.source "SourceFile"


# direct methods
.method public static final a(Landroidx/appcompat/view/menu/cm;I)V
    .locals 3

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/cm;->d()Landroidx/appcompat/view/menu/wg;

    move-result-object v0

    const/4 v1, 0x4

    if-ne p1, v1, :cond_0

    const/4 v1, 0x1

    goto :goto_0

    :cond_0
    const/4 v1, 0x0

    :goto_0
    if-nez v1, :cond_2

    instance-of v2, v0, Landroidx/appcompat/view/menu/am;

    if-eqz v2, :cond_2

    invoke-static {p1}, Landroidx/appcompat/view/menu/dm;->b(I)Z

    move-result p1

    iget v2, p0, Landroidx/appcompat/view/menu/cm;->o:I

    invoke-static {v2}, Landroidx/appcompat/view/menu/dm;->b(I)Z

    move-result v2

    if-ne p1, v2, :cond_2

    move-object p1, v0

    check-cast p1, Landroidx/appcompat/view/menu/am;

    iget-object p1, p1, Landroidx/appcompat/view/menu/am;->p:Landroidx/appcompat/view/menu/mh;

    invoke-interface {v0}, Landroidx/appcompat/view/menu/wg;->b()Landroidx/appcompat/view/menu/jh;

    move-result-object v0

    invoke-virtual {p1, v0}, Landroidx/appcompat/view/menu/mh;->D(Landroidx/appcompat/view/menu/jh;)Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-virtual {p1, v0, p0}, Landroidx/appcompat/view/menu/mh;->A(Landroidx/appcompat/view/menu/jh;Ljava/lang/Runnable;)V

    goto :goto_1

    :cond_1
    invoke-static {p0}, Landroidx/appcompat/view/menu/dm;->e(Landroidx/appcompat/view/menu/cm;)V

    goto :goto_1

    :cond_2
    invoke-static {p0, v0, v1}, Landroidx/appcompat/view/menu/dm;->d(Landroidx/appcompat/view/menu/cm;Landroidx/appcompat/view/menu/wg;Z)V

    :goto_1
    return-void
.end method

.method public static final b(I)Z
    .locals 2

    const/4 v0, 0x1

    if-eq p0, v0, :cond_1

    const/4 v1, 0x2

    if-ne p0, v1, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :cond_1
    :goto_0
    return v0
.end method

.method public static final c(I)Z
    .locals 1

    const/4 v0, 0x2

    if-ne p0, v0, :cond_0

    const/4 p0, 0x1

    goto :goto_0

    :cond_0
    const/4 p0, 0x0

    :goto_0
    return p0
.end method

.method public static final d(Landroidx/appcompat/view/menu/cm;Landroidx/appcompat/view/menu/wg;Z)V
    .locals 3

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/cm;->j()Ljava/lang/Object;

    move-result-object v0

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/cm;->e(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v1

    if-eqz v1, :cond_0

    sget-object p0, Landroidx/appcompat/view/menu/jp0;->m:Landroidx/appcompat/view/menu/jp0$a;

    invoke-static {v1}, Landroidx/appcompat/view/menu/kp0;->a(Ljava/lang/Throwable;)Ljava/lang/Object;

    move-result-object p0

    :goto_0
    invoke-static {p0}, Landroidx/appcompat/view/menu/jp0;->a(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    goto :goto_1

    :cond_0
    sget-object v1, Landroidx/appcompat/view/menu/jp0;->m:Landroidx/appcompat/view/menu/jp0$a;

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/cm;->h(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    goto :goto_0

    :goto_1
    if-eqz p2, :cond_2

    const-string p2, "null cannot be cast to non-null type kotlinx.coroutines.internal.DispatchedContinuation<T of kotlinx.coroutines.DispatchedTaskKt.resume>"

    invoke-static {p1, p2}, Landroidx/appcompat/view/menu/x50;->c(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Landroidx/appcompat/view/menu/am;

    iget-object p2, p1, Landroidx/appcompat/view/menu/am;->q:Landroidx/appcompat/view/menu/wg;

    iget-object v0, p1, Landroidx/appcompat/view/menu/am;->s:Ljava/lang/Object;

    invoke-interface {p2}, Landroidx/appcompat/view/menu/wg;->b()Landroidx/appcompat/view/menu/jh;

    move-result-object v1

    invoke-static {v1, v0}, Landroidx/appcompat/view/menu/e01;->c(Landroidx/appcompat/view/menu/jh;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    sget-object v2, Landroidx/appcompat/view/menu/e01;->a:Landroidx/appcompat/view/menu/iy0;

    if-eq v0, v2, :cond_1

    invoke-static {p2, v1, v0}, Landroidx/appcompat/view/menu/kh;->f(Landroidx/appcompat/view/menu/wg;Landroidx/appcompat/view/menu/jh;Ljava/lang/Object;)Landroidx/appcompat/view/menu/i31;

    :cond_1
    :try_start_0
    iget-object p1, p1, Landroidx/appcompat/view/menu/am;->q:Landroidx/appcompat/view/menu/wg;

    invoke-interface {p1, p0}, Landroidx/appcompat/view/menu/wg;->n(Ljava/lang/Object;)V

    sget-object p0, Landroidx/appcompat/view/menu/n31;->a:Landroidx/appcompat/view/menu/n31;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-static {v1, v0}, Landroidx/appcompat/view/menu/e01;->a(Landroidx/appcompat/view/menu/jh;Ljava/lang/Object;)V

    goto :goto_2

    :catchall_0
    move-exception p0

    invoke-static {v1, v0}, Landroidx/appcompat/view/menu/e01;->a(Landroidx/appcompat/view/menu/jh;Ljava/lang/Object;)V

    throw p0

    :cond_2
    invoke-interface {p1, p0}, Landroidx/appcompat/view/menu/wg;->n(Ljava/lang/Object;)V

    :goto_2
    return-void
.end method

.method public static final e(Landroidx/appcompat/view/menu/cm;)V
    .locals 4

    sget-object v0, Landroidx/appcompat/view/menu/f01;->a:Landroidx/appcompat/view/menu/f01;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/f01;->a()Landroidx/appcompat/view/menu/ap;

    move-result-object v0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ap;->L()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-virtual {v0, p0}, Landroidx/appcompat/view/menu/ap;->H(Landroidx/appcompat/view/menu/cm;)V

    goto :goto_1

    :cond_0
    const/4 v1, 0x1

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/ap;->J(Z)V

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/cm;->d()Landroidx/appcompat/view/menu/wg;

    move-result-object v2

    invoke-static {p0, v2, v1}, Landroidx/appcompat/view/menu/dm;->d(Landroidx/appcompat/view/menu/cm;Landroidx/appcompat/view/menu/wg;Z)V

    :cond_1
    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ap;->N()Z

    move-result v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-nez v2, :cond_1

    :goto_0
    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/ap;->F(Z)V

    goto :goto_1

    :catchall_0
    move-exception v2

    const/4 v3, 0x0

    :try_start_1
    invoke-virtual {p0, v2, v3}, Landroidx/appcompat/view/menu/cm;->i(Ljava/lang/Throwable;Ljava/lang/Throwable;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    goto :goto_0

    :goto_1
    return-void

    :catchall_1
    move-exception p0

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/ap;->F(Z)V

    throw p0
.end method
