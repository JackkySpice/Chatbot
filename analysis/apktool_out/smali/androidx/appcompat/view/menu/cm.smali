.class public abstract Landroidx/appcompat/view/menu/cm;
.super Landroidx/appcompat/view/menu/uy0;
.source "SourceFile"


# instance fields
.field public o:I


# direct methods
.method public constructor <init>(I)V
    .locals 0

    invoke-direct {p0}, Landroidx/appcompat/view/menu/uy0;-><init>()V

    iput p1, p0, Landroidx/appcompat/view/menu/cm;->o:I

    return-void
.end method


# virtual methods
.method public abstract c(Ljava/lang/Object;Ljava/lang/Throwable;)V
.end method

.method public abstract d()Landroidx/appcompat/view/menu/wg;
.end method

.method public e(Ljava/lang/Object;)Ljava/lang/Throwable;
    .locals 2

    instance-of v0, p1, Landroidx/appcompat/view/menu/md;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    check-cast p1, Landroidx/appcompat/view/menu/md;

    goto :goto_0

    :cond_0
    move-object p1, v1

    :goto_0
    if-eqz p1, :cond_1

    iget-object v1, p1, Landroidx/appcompat/view/menu/md;->a:Ljava/lang/Throwable;

    :cond_1
    return-object v1
.end method

.method public h(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    return-object p1
.end method

.method public final i(Ljava/lang/Throwable;Ljava/lang/Throwable;)V
    .locals 2

    if-nez p1, :cond_0

    if-nez p2, :cond_0

    return-void

    :cond_0
    if-eqz p1, :cond_1

    if-eqz p2, :cond_1

    invoke-static {p1, p2}, Landroidx/appcompat/view/menu/np;->a(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    :cond_1
    if-nez p1, :cond_2

    move-object p1, p2

    :cond_2
    new-instance p2, Landroidx/appcompat/view/menu/xh;

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "Fatal exception in coroutines machinery for "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ". Please read KDoc to \'handleFatalException\' method and report this incident to maintainers"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {p1}, Landroidx/appcompat/view/menu/x50;->b(Ljava/lang/Object;)V

    invoke-direct {p2, v0, p1}, Landroidx/appcompat/view/menu/xh;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/cm;->d()Landroidx/appcompat/view/menu/wg;

    move-result-object p1

    invoke-interface {p1}, Landroidx/appcompat/view/menu/wg;->b()Landroidx/appcompat/view/menu/jh;

    move-result-object p1

    invoke-static {p1, p2}, Landroidx/appcompat/view/menu/qh;->a(Landroidx/appcompat/view/menu/jh;Ljava/lang/Throwable;)V

    return-void
.end method

.method public abstract j()Ljava/lang/Object;
.end method

.method public final run()V
    .locals 9

    iget-object v0, p0, Landroidx/appcompat/view/menu/uy0;->n:Landroidx/appcompat/view/menu/yy0;

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/cm;->d()Landroidx/appcompat/view/menu/wg;

    move-result-object v1

    const-string v2, "null cannot be cast to non-null type kotlinx.coroutines.internal.DispatchedContinuation<T of kotlinx.coroutines.DispatchedTask>"

    invoke-static {v1, v2}, Landroidx/appcompat/view/menu/x50;->c(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v1, Landroidx/appcompat/view/menu/am;

    iget-object v2, v1, Landroidx/appcompat/view/menu/am;->q:Landroidx/appcompat/view/menu/wg;

    iget-object v1, v1, Landroidx/appcompat/view/menu/am;->s:Ljava/lang/Object;

    invoke-interface {v2}, Landroidx/appcompat/view/menu/wg;->b()Landroidx/appcompat/view/menu/jh;

    move-result-object v3

    invoke-static {v3, v1}, Landroidx/appcompat/view/menu/e01;->c(Landroidx/appcompat/view/menu/jh;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    sget-object v4, Landroidx/appcompat/view/menu/e01;->a:Landroidx/appcompat/view/menu/iy0;

    if-eq v1, v4, :cond_0

    invoke-static {v2, v3, v1}, Landroidx/appcompat/view/menu/kh;->f(Landroidx/appcompat/view/menu/wg;Landroidx/appcompat/view/menu/jh;Ljava/lang/Object;)Landroidx/appcompat/view/menu/i31;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    :cond_0
    :try_start_1
    invoke-interface {v2}, Landroidx/appcompat/view/menu/wg;->b()Landroidx/appcompat/view/menu/jh;

    move-result-object v4

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/cm;->j()Ljava/lang/Object;

    move-result-object v5

    invoke-virtual {p0, v5}, Landroidx/appcompat/view/menu/cm;->e(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v6

    const/4 v7, 0x0

    if-nez v6, :cond_1

    iget v8, p0, Landroidx/appcompat/view/menu/cm;->o:I

    invoke-static {v8}, Landroidx/appcompat/view/menu/dm;->b(I)Z

    move-result v8

    if-eqz v8, :cond_1

    sget-object v8, Landroidx/appcompat/view/menu/n60;->d:Landroidx/appcompat/view/menu/n60$b;

    invoke-interface {v4, v8}, Landroidx/appcompat/view/menu/jh;->d(Landroidx/appcompat/view/menu/jh$c;)Landroidx/appcompat/view/menu/jh$b;

    move-result-object v4

    check-cast v4, Landroidx/appcompat/view/menu/n60;

    goto :goto_0

    :catchall_0
    move-exception v2

    goto :goto_3

    :cond_1
    move-object v4, v7

    :goto_0
    if-eqz v4, :cond_2

    invoke-interface {v4}, Landroidx/appcompat/view/menu/n60;->c()Z

    move-result v8

    if-nez v8, :cond_2

    invoke-interface {v4}, Landroidx/appcompat/view/menu/n60;->w()Ljava/util/concurrent/CancellationException;

    move-result-object v4

    invoke-virtual {p0, v5, v4}, Landroidx/appcompat/view/menu/cm;->c(Ljava/lang/Object;Ljava/lang/Throwable;)V

    sget-object v5, Landroidx/appcompat/view/menu/jp0;->m:Landroidx/appcompat/view/menu/jp0$a;

    invoke-static {v4}, Landroidx/appcompat/view/menu/kp0;->a(Ljava/lang/Throwable;)Ljava/lang/Object;

    move-result-object v4

    invoke-static {v4}, Landroidx/appcompat/view/menu/jp0;->a(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v4

    invoke-interface {v2, v4}, Landroidx/appcompat/view/menu/wg;->n(Ljava/lang/Object;)V

    goto :goto_1

    :cond_2
    if-eqz v6, :cond_3

    sget-object v4, Landroidx/appcompat/view/menu/jp0;->m:Landroidx/appcompat/view/menu/jp0$a;

    invoke-static {v6}, Landroidx/appcompat/view/menu/kp0;->a(Ljava/lang/Throwable;)Ljava/lang/Object;

    move-result-object v4

    invoke-static {v4}, Landroidx/appcompat/view/menu/jp0;->a(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v4

    invoke-interface {v2, v4}, Landroidx/appcompat/view/menu/wg;->n(Ljava/lang/Object;)V

    goto :goto_1

    :cond_3
    sget-object v4, Landroidx/appcompat/view/menu/jp0;->m:Landroidx/appcompat/view/menu/jp0$a;

    invoke-virtual {p0, v5}, Landroidx/appcompat/view/menu/cm;->h(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v4

    invoke-static {v4}, Landroidx/appcompat/view/menu/jp0;->a(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v4

    invoke-interface {v2, v4}, Landroidx/appcompat/view/menu/wg;->n(Ljava/lang/Object;)V

    :goto_1
    sget-object v2, Landroidx/appcompat/view/menu/n31;->a:Landroidx/appcompat/view/menu/n31;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :try_start_2
    invoke-static {v3, v1}, Landroidx/appcompat/view/menu/e01;->a(Landroidx/appcompat/view/menu/jh;Ljava/lang/Object;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    :try_start_3
    invoke-interface {v0}, Landroidx/appcompat/view/menu/yy0;->a()V

    sget-object v0, Landroidx/appcompat/view/menu/n31;->a:Landroidx/appcompat/view/menu/n31;

    invoke-static {v0}, Landroidx/appcompat/view/menu/jp0;->a(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    goto :goto_2

    :catchall_1
    move-exception v0

    sget-object v1, Landroidx/appcompat/view/menu/jp0;->m:Landroidx/appcompat/view/menu/jp0$a;

    invoke-static {v0}, Landroidx/appcompat/view/menu/kp0;->a(Ljava/lang/Throwable;)Ljava/lang/Object;

    move-result-object v0

    invoke-static {v0}, Landroidx/appcompat/view/menu/jp0;->a(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    :goto_2
    invoke-static {v0}, Landroidx/appcompat/view/menu/jp0;->b(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v0

    invoke-virtual {p0, v7, v0}, Landroidx/appcompat/view/menu/cm;->i(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    goto :goto_6

    :catchall_2
    move-exception v1

    goto :goto_4

    :goto_3
    :try_start_4
    invoke-static {v3, v1}, Landroidx/appcompat/view/menu/e01;->a(Landroidx/appcompat/view/menu/jh;Ljava/lang/Object;)V

    throw v2
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    :goto_4
    :try_start_5
    sget-object v2, Landroidx/appcompat/view/menu/jp0;->m:Landroidx/appcompat/view/menu/jp0$a;

    invoke-interface {v0}, Landroidx/appcompat/view/menu/yy0;->a()V

    sget-object v0, Landroidx/appcompat/view/menu/n31;->a:Landroidx/appcompat/view/menu/n31;

    invoke-static {v0}, Landroidx/appcompat/view/menu/jp0;->a(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    goto :goto_5

    :catchall_3
    move-exception v0

    sget-object v2, Landroidx/appcompat/view/menu/jp0;->m:Landroidx/appcompat/view/menu/jp0$a;

    invoke-static {v0}, Landroidx/appcompat/view/menu/kp0;->a(Ljava/lang/Throwable;)Ljava/lang/Object;

    move-result-object v0

    invoke-static {v0}, Landroidx/appcompat/view/menu/jp0;->a(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    :goto_5
    invoke-static {v0}, Landroidx/appcompat/view/menu/jp0;->b(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v0

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/cm;->i(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    :goto_6
    return-void
.end method
