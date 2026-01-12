.class public final Landroidx/appcompat/view/menu/u8$a;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/ya;
.implements Landroidx/appcompat/view/menu/i71;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/u8;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x11
    name = "a"
.end annotation


# instance fields
.field public m:Ljava/lang/Object;

.field public n:Landroidx/appcompat/view/menu/x9;

.field public final synthetic o:Landroidx/appcompat/view/menu/u8;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/u8;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/u8$a;->o:Landroidx/appcompat/view/menu/u8;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    invoke-static {}, Landroidx/appcompat/view/menu/v8;->m()Landroidx/appcompat/view/menu/iy0;

    move-result-object p1

    iput-object p1, p0, Landroidx/appcompat/view/menu/u8$a;->m:Ljava/lang/Object;

    return-void
.end method

.method public static final synthetic c(Landroidx/appcompat/view/menu/u8$a;)V
    .locals 0

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/u8$a;->h()V

    return-void
.end method

.method public static final synthetic d(Landroidx/appcompat/view/menu/u8$a;Landroidx/appcompat/view/menu/x9;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/u8$a;->n:Landroidx/appcompat/view/menu/x9;

    return-void
.end method

.method public static final synthetic e(Landroidx/appcompat/view/menu/u8$a;Ljava/lang/Object;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/u8$a;->m:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public a(Landroidx/appcompat/view/menu/fs0;I)V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/u8$a;->n:Landroidx/appcompat/view/menu/x9;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1, p2}, Landroidx/appcompat/view/menu/x9;->a(Landroidx/appcompat/view/menu/fs0;I)V

    :cond_0
    return-void
.end method

.method public b(Landroidx/appcompat/view/menu/wg;)Ljava/lang/Object;
    .locals 14

    iget-object v6, p0, Landroidx/appcompat/view/menu/u8$a;->o:Landroidx/appcompat/view/menu/u8;

    const/4 v7, 0x0

    invoke-static {}, Landroidx/appcompat/view/menu/u8;->d()Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    move-result-object v0

    invoke-virtual {v0, v6}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/cb;

    :goto_0
    invoke-virtual {v6}, Landroidx/appcompat/view/menu/u8;->S()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/u8$a;->g()Z

    move-result p1

    invoke-static {p1}, Landroidx/appcompat/view/menu/q8;->a(Z)Ljava/lang/Boolean;

    move-result-object p1

    goto :goto_2

    :cond_0
    invoke-static {}, Landroidx/appcompat/view/menu/u8;->f()Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    move-result-object v1

    invoke-virtual {v1, v6}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->getAndIncrement(Ljava/lang/Object;)J

    move-result-wide v11

    sget v1, Landroidx/appcompat/view/menu/v8;->b:I

    int-to-long v2, v1

    div-long v2, v11, v2

    int-to-long v4, v1

    rem-long v4, v11, v4

    long-to-int v10, v4

    iget-wide v4, v0, Landroidx/appcompat/view/menu/fs0;->o:J

    cmp-long v1, v4, v2

    if-eqz v1, :cond_2

    invoke-static {v6, v2, v3, v0}, Landroidx/appcompat/view/menu/u8;->a(Landroidx/appcompat/view/menu/u8;JLandroidx/appcompat/view/menu/cb;)Landroidx/appcompat/view/menu/cb;

    move-result-object v1

    if-nez v1, :cond_1

    goto :goto_0

    :cond_1
    move-object v9, v1

    goto :goto_1

    :cond_2
    move-object v9, v0

    :goto_1
    move-object v0, v6

    move-object v1, v9

    move v2, v10

    move-wide v3, v11

    move-object v5, v7

    invoke-static/range {v0 .. v5}, Landroidx/appcompat/view/menu/u8;->n(Landroidx/appcompat/view/menu/u8;Landroidx/appcompat/view/menu/cb;IJLjava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    invoke-static {}, Landroidx/appcompat/view/menu/v8;->r()Landroidx/appcompat/view/menu/iy0;

    move-result-object v1

    if-eq v0, v1, :cond_6

    invoke-static {}, Landroidx/appcompat/view/menu/v8;->h()Landroidx/appcompat/view/menu/iy0;

    move-result-object v1

    if-ne v0, v1, :cond_4

    invoke-virtual {v6}, Landroidx/appcompat/view/menu/u8;->L()J

    move-result-wide v0

    cmp-long v0, v11, v0

    if-gez v0, :cond_3

    invoke-virtual {v9}, Landroidx/appcompat/view/menu/ye;->b()V

    :cond_3
    move-object v0, v9

    goto :goto_0

    :cond_4
    invoke-static {}, Landroidx/appcompat/view/menu/v8;->s()Landroidx/appcompat/view/menu/iy0;

    move-result-object v1

    if-ne v0, v1, :cond_5

    move-object v8, p0

    move-object v13, p1

    invoke-virtual/range {v8 .. v13}, Landroidx/appcompat/view/menu/u8$a;->f(Landroidx/appcompat/view/menu/cb;IJLandroidx/appcompat/view/menu/wg;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_5
    invoke-virtual {v9}, Landroidx/appcompat/view/menu/ye;->b()V

    iput-object v0, p0, Landroidx/appcompat/view/menu/u8$a;->m:Ljava/lang/Object;

    const/4 p1, 0x1

    invoke-static {p1}, Landroidx/appcompat/view/menu/q8;->a(Z)Ljava/lang/Boolean;

    move-result-object p1

    :goto_2
    return-object p1

    :cond_6
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "unreachable"

    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final f(Landroidx/appcompat/view/menu/cb;IJLandroidx/appcompat/view/menu/wg;)Ljava/lang/Object;
    .locals 10

    iget-object v6, p0, Landroidx/appcompat/view/menu/u8$a;->o:Landroidx/appcompat/view/menu/u8;

    invoke-static {p5}, Landroidx/appcompat/view/menu/y50;->b(Landroidx/appcompat/view/menu/wg;)Landroidx/appcompat/view/menu/wg;

    move-result-object v0

    invoke-static {v0}, Landroidx/appcompat/view/menu/z9;->a(Landroidx/appcompat/view/menu/wg;)Landroidx/appcompat/view/menu/x9;

    move-result-object v7

    :try_start_0
    invoke-static {p0, v7}, Landroidx/appcompat/view/menu/u8$a;->d(Landroidx/appcompat/view/menu/u8$a;Landroidx/appcompat/view/menu/x9;)V

    move-object v0, v6

    move-object v1, p1

    move v2, p2

    move-wide v3, p3

    move-object v5, p0

    invoke-static/range {v0 .. v5}, Landroidx/appcompat/view/menu/u8;->n(Landroidx/appcompat/view/menu/u8;Landroidx/appcompat/view/menu/cb;IJLjava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    invoke-static {}, Landroidx/appcompat/view/menu/v8;->r()Landroidx/appcompat/view/menu/iy0;

    move-result-object v1

    if-ne v0, v1, :cond_0

    invoke-static {v6, p0, p1, p2}, Landroidx/appcompat/view/menu/u8;->l(Landroidx/appcompat/view/menu/u8;Landroidx/appcompat/view/menu/i71;Landroidx/appcompat/view/menu/cb;I)V

    goto/16 :goto_2

    :catchall_0
    move-exception p1

    goto/16 :goto_3

    :cond_0
    invoke-static {}, Landroidx/appcompat/view/menu/v8;->h()Landroidx/appcompat/view/menu/iy0;

    move-result-object p2

    const/4 v8, 0x1

    const/4 v9, 0x0

    if-ne v0, p2, :cond_a

    invoke-virtual {v6}, Landroidx/appcompat/view/menu/u8;->L()J

    move-result-wide v0

    cmp-long p2, p3, v0

    if-gez p2, :cond_1

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/ye;->b()V

    :cond_1
    invoke-static {}, Landroidx/appcompat/view/menu/u8;->d()Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    move-result-object p1

    invoke-virtual {p1, v6}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroidx/appcompat/view/menu/cb;

    :cond_2
    :goto_0
    invoke-virtual {v6}, Landroidx/appcompat/view/menu/u8;->S()Z

    move-result p2

    if-eqz p2, :cond_3

    invoke-static {p0}, Landroidx/appcompat/view/menu/u8$a;->c(Landroidx/appcompat/view/menu/u8$a;)V

    goto/16 :goto_2

    :cond_3
    invoke-static {}, Landroidx/appcompat/view/menu/u8;->f()Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    move-result-object p2

    invoke-virtual {p2, v6}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->getAndIncrement(Ljava/lang/Object;)J

    move-result-wide p2

    sget p4, Landroidx/appcompat/view/menu/v8;->b:I

    int-to-long v0, p4

    div-long v0, p2, v0

    int-to-long v2, p4

    rem-long v2, p2, v2

    long-to-int p4, v2

    iget-wide v2, p1, Landroidx/appcompat/view/menu/fs0;->o:J

    cmp-long v2, v2, v0

    if-eqz v2, :cond_5

    invoke-static {v6, v0, v1, p1}, Landroidx/appcompat/view/menu/u8;->a(Landroidx/appcompat/view/menu/u8;JLandroidx/appcompat/view/menu/cb;)Landroidx/appcompat/view/menu/cb;

    move-result-object v0

    if-nez v0, :cond_4

    goto :goto_0

    :cond_4
    move-object p1, v0

    :cond_5
    move-object v0, v6

    move-object v1, p1

    move v2, p4

    move-wide v3, p2

    move-object v5, p0

    invoke-static/range {v0 .. v5}, Landroidx/appcompat/view/menu/u8;->n(Landroidx/appcompat/view/menu/u8;Landroidx/appcompat/view/menu/cb;IJLjava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    invoke-static {}, Landroidx/appcompat/view/menu/v8;->r()Landroidx/appcompat/view/menu/iy0;

    move-result-object v1

    if-ne v0, v1, :cond_6

    invoke-static {v6, p0, p1, p4}, Landroidx/appcompat/view/menu/u8;->l(Landroidx/appcompat/view/menu/u8;Landroidx/appcompat/view/menu/i71;Landroidx/appcompat/view/menu/cb;I)V

    goto :goto_2

    :cond_6
    invoke-static {}, Landroidx/appcompat/view/menu/v8;->h()Landroidx/appcompat/view/menu/iy0;

    move-result-object p4

    if-ne v0, p4, :cond_7

    invoke-virtual {v6}, Landroidx/appcompat/view/menu/u8;->L()J

    move-result-wide v0

    cmp-long p2, p2, v0

    if-gez p2, :cond_2

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/ye;->b()V

    goto :goto_0

    :cond_7
    invoke-static {}, Landroidx/appcompat/view/menu/v8;->s()Landroidx/appcompat/view/menu/iy0;

    move-result-object p2

    if-eq v0, p2, :cond_9

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/ye;->b()V

    invoke-static {p0, v0}, Landroidx/appcompat/view/menu/u8$a;->e(Landroidx/appcompat/view/menu/u8$a;Ljava/lang/Object;)V

    invoke-static {p0, v9}, Landroidx/appcompat/view/menu/u8$a;->d(Landroidx/appcompat/view/menu/u8$a;Landroidx/appcompat/view/menu/x9;)V

    invoke-static {v8}, Landroidx/appcompat/view/menu/q8;->a(Z)Ljava/lang/Boolean;

    move-result-object p1

    iget-object p2, v6, Landroidx/appcompat/view/menu/u8;->n:Landroidx/appcompat/view/menu/jw;

    if-eqz p2, :cond_8

    invoke-virtual {v7}, Landroidx/appcompat/view/menu/x9;->b()Landroidx/appcompat/view/menu/jh;

    move-result-object p3

    invoke-static {p2, v0, p3}, Landroidx/appcompat/view/menu/jg0;->a(Landroidx/appcompat/view/menu/jw;Ljava/lang/Object;Landroidx/appcompat/view/menu/jh;)Landroidx/appcompat/view/menu/jw;

    move-result-object v9

    :cond_8
    :goto_1
    invoke-virtual {v7, p1, v9}, Landroidx/appcompat/view/menu/x9;->K(Ljava/lang/Object;Landroidx/appcompat/view/menu/jw;)V

    goto :goto_2

    :cond_9
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "unexpected"

    invoke-virtual {p2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_a
    invoke-virtual {p1}, Landroidx/appcompat/view/menu/ye;->b()V

    invoke-static {p0, v0}, Landroidx/appcompat/view/menu/u8$a;->e(Landroidx/appcompat/view/menu/u8$a;Ljava/lang/Object;)V

    invoke-static {p0, v9}, Landroidx/appcompat/view/menu/u8$a;->d(Landroidx/appcompat/view/menu/u8$a;Landroidx/appcompat/view/menu/x9;)V

    invoke-static {v8}, Landroidx/appcompat/view/menu/q8;->a(Z)Ljava/lang/Boolean;

    move-result-object p1

    iget-object p2, v6, Landroidx/appcompat/view/menu/u8;->n:Landroidx/appcompat/view/menu/jw;

    if-eqz p2, :cond_8

    invoke-virtual {v7}, Landroidx/appcompat/view/menu/x9;->b()Landroidx/appcompat/view/menu/jh;

    move-result-object p3

    invoke-static {p2, v0, p3}, Landroidx/appcompat/view/menu/jg0;->a(Landroidx/appcompat/view/menu/jw;Ljava/lang/Object;Landroidx/appcompat/view/menu/jh;)Landroidx/appcompat/view/menu/jw;

    move-result-object v9
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_1

    :goto_2
    invoke-virtual {v7}, Landroidx/appcompat/view/menu/x9;->w()Ljava/lang/Object;

    move-result-object p1

    invoke-static {}, Landroidx/appcompat/view/menu/y50;->c()Ljava/lang/Object;

    move-result-object p2

    if-ne p1, p2, :cond_b

    invoke-static {p5}, Landroidx/appcompat/view/menu/fj;->c(Landroidx/appcompat/view/menu/wg;)V

    :cond_b
    return-object p1

    :goto_3
    invoke-virtual {v7}, Landroidx/appcompat/view/menu/x9;->I()V

    throw p1
.end method

.method public final g()Z
    .locals 1

    invoke-static {}, Landroidx/appcompat/view/menu/v8;->z()Landroidx/appcompat/view/menu/iy0;

    move-result-object v0

    iput-object v0, p0, Landroidx/appcompat/view/menu/u8$a;->m:Ljava/lang/Object;

    iget-object v0, p0, Landroidx/appcompat/view/menu/u8$a;->o:Landroidx/appcompat/view/menu/u8;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/u8;->H()Ljava/lang/Throwable;

    move-result-object v0

    if-nez v0, :cond_0

    const/4 v0, 0x0

    return v0

    :cond_0
    invoke-static {v0}, Landroidx/appcompat/view/menu/iw0;->a(Ljava/lang/Throwable;)Ljava/lang/Throwable;

    move-result-object v0

    throw v0
.end method

.method public final h()V
    .locals 3

    iget-object v0, p0, Landroidx/appcompat/view/menu/u8$a;->n:Landroidx/appcompat/view/menu/x9;

    invoke-static {v0}, Landroidx/appcompat/view/menu/x50;->b(Ljava/lang/Object;)V

    const/4 v1, 0x0

    iput-object v1, p0, Landroidx/appcompat/view/menu/u8$a;->n:Landroidx/appcompat/view/menu/x9;

    invoke-static {}, Landroidx/appcompat/view/menu/v8;->z()Landroidx/appcompat/view/menu/iy0;

    move-result-object v1

    iput-object v1, p0, Landroidx/appcompat/view/menu/u8$a;->m:Ljava/lang/Object;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u8$a;->o:Landroidx/appcompat/view/menu/u8;

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/u8;->H()Ljava/lang/Throwable;

    move-result-object v1

    if-nez v1, :cond_0

    sget-object v1, Landroidx/appcompat/view/menu/jp0;->m:Landroidx/appcompat/view/menu/jp0$a;

    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {v1}, Landroidx/appcompat/view/menu/jp0;->a(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    invoke-interface {v0, v1}, Landroidx/appcompat/view/menu/wg;->n(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    sget-object v2, Landroidx/appcompat/view/menu/jp0;->m:Landroidx/appcompat/view/menu/jp0$a;

    invoke-static {v1}, Landroidx/appcompat/view/menu/kp0;->a(Ljava/lang/Throwable;)Ljava/lang/Object;

    move-result-object v1

    invoke-static {v1}, Landroidx/appcompat/view/menu/jp0;->a(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    invoke-interface {v0, v1}, Landroidx/appcompat/view/menu/wg;->n(Ljava/lang/Object;)V

    :goto_0
    return-void
.end method

.method public final i(Ljava/lang/Object;)Z
    .locals 4

    iget-object v0, p0, Landroidx/appcompat/view/menu/u8$a;->n:Landroidx/appcompat/view/menu/x9;

    invoke-static {v0}, Landroidx/appcompat/view/menu/x50;->b(Ljava/lang/Object;)V

    const/4 v1, 0x0

    iput-object v1, p0, Landroidx/appcompat/view/menu/u8$a;->n:Landroidx/appcompat/view/menu/x9;

    iput-object p1, p0, Landroidx/appcompat/view/menu/u8$a;->m:Ljava/lang/Object;

    sget-object v2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    iget-object v3, p0, Landroidx/appcompat/view/menu/u8$a;->o:Landroidx/appcompat/view/menu/u8;

    iget-object v3, v3, Landroidx/appcompat/view/menu/u8;->n:Landroidx/appcompat/view/menu/jw;

    if-eqz v3, :cond_0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/x9;->b()Landroidx/appcompat/view/menu/jh;

    move-result-object v1

    invoke-static {v3, p1, v1}, Landroidx/appcompat/view/menu/jg0;->a(Landroidx/appcompat/view/menu/jw;Ljava/lang/Object;Landroidx/appcompat/view/menu/jh;)Landroidx/appcompat/view/menu/jw;

    move-result-object v1

    :cond_0
    invoke-static {v0, v2, v1}, Landroidx/appcompat/view/menu/v8;->u(Landroidx/appcompat/view/menu/w9;Ljava/lang/Object;Landroidx/appcompat/view/menu/jw;)Z

    move-result p1

    return p1
.end method

.method public final j()V
    .locals 3

    iget-object v0, p0, Landroidx/appcompat/view/menu/u8$a;->n:Landroidx/appcompat/view/menu/x9;

    invoke-static {v0}, Landroidx/appcompat/view/menu/x50;->b(Ljava/lang/Object;)V

    const/4 v1, 0x0

    iput-object v1, p0, Landroidx/appcompat/view/menu/u8$a;->n:Landroidx/appcompat/view/menu/x9;

    invoke-static {}, Landroidx/appcompat/view/menu/v8;->z()Landroidx/appcompat/view/menu/iy0;

    move-result-object v1

    iput-object v1, p0, Landroidx/appcompat/view/menu/u8$a;->m:Ljava/lang/Object;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u8$a;->o:Landroidx/appcompat/view/menu/u8;

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/u8;->H()Ljava/lang/Throwable;

    move-result-object v1

    if-nez v1, :cond_0

    sget-object v1, Landroidx/appcompat/view/menu/jp0;->m:Landroidx/appcompat/view/menu/jp0$a;

    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {v1}, Landroidx/appcompat/view/menu/jp0;->a(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    invoke-interface {v0, v1}, Landroidx/appcompat/view/menu/wg;->n(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    sget-object v2, Landroidx/appcompat/view/menu/jp0;->m:Landroidx/appcompat/view/menu/jp0$a;

    invoke-static {v1}, Landroidx/appcompat/view/menu/kp0;->a(Ljava/lang/Throwable;)Ljava/lang/Object;

    move-result-object v1

    invoke-static {v1}, Landroidx/appcompat/view/menu/jp0;->a(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    invoke-interface {v0, v1}, Landroidx/appcompat/view/menu/wg;->n(Ljava/lang/Object;)V

    :goto_0
    return-void
.end method

.method public next()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/u8$a;->m:Ljava/lang/Object;

    invoke-static {}, Landroidx/appcompat/view/menu/v8;->m()Landroidx/appcompat/view/menu/iy0;

    move-result-object v1

    if-eq v0, v1, :cond_1

    invoke-static {}, Landroidx/appcompat/view/menu/v8;->m()Landroidx/appcompat/view/menu/iy0;

    move-result-object v1

    iput-object v1, p0, Landroidx/appcompat/view/menu/u8$a;->m:Ljava/lang/Object;

    invoke-static {}, Landroidx/appcompat/view/menu/v8;->z()Landroidx/appcompat/view/menu/iy0;

    move-result-object v1

    if-eq v0, v1, :cond_0

    return-object v0

    :cond_0
    iget-object v0, p0, Landroidx/appcompat/view/menu/u8$a;->o:Landroidx/appcompat/view/menu/u8;

    invoke-static {v0}, Landroidx/appcompat/view/menu/u8;->c(Landroidx/appcompat/view/menu/u8;)Ljava/lang/Throwable;

    move-result-object v0

    invoke-static {v0}, Landroidx/appcompat/view/menu/iw0;->a(Ljava/lang/Throwable;)Ljava/lang/Throwable;

    move-result-object v0

    throw v0

    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "`hasNext()` has not been invoked"

    invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method
