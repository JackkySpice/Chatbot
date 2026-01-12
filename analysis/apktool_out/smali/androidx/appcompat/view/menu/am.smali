.class public final Landroidx/appcompat/view/menu/am;
.super Landroidx/appcompat/view/menu/cm;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/vh;
.implements Landroidx/appcompat/view/menu/wg;


# static fields
.field public static final t:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;


# instance fields
.field private volatile _reusableCancellableContinuation:Ljava/lang/Object;

.field public final p:Landroidx/appcompat/view/menu/mh;

.field public final q:Landroidx/appcompat/view/menu/wg;

.field public r:Ljava/lang/Object;

.field public final s:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    const-class v0, Ljava/lang/Object;

    const-string v1, "_reusableCancellableContinuation"

    const-class v2, Landroidx/appcompat/view/menu/am;

    invoke-static {v2, v0, v1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    move-result-object v0

    sput-object v0, Landroidx/appcompat/view/menu/am;->t:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    return-void
.end method

.method public constructor <init>(Landroidx/appcompat/view/menu/mh;Landroidx/appcompat/view/menu/wg;)V
    .locals 1

    const/4 v0, -0x1

    invoke-direct {p0, v0}, Landroidx/appcompat/view/menu/cm;-><init>(I)V

    iput-object p1, p0, Landroidx/appcompat/view/menu/am;->p:Landroidx/appcompat/view/menu/mh;

    iput-object p2, p0, Landroidx/appcompat/view/menu/am;->q:Landroidx/appcompat/view/menu/wg;

    invoke-static {}, Landroidx/appcompat/view/menu/bm;->a()Landroidx/appcompat/view/menu/iy0;

    move-result-object p1

    iput-object p1, p0, Landroidx/appcompat/view/menu/am;->r:Ljava/lang/Object;

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/am;->b()Landroidx/appcompat/view/menu/jh;

    move-result-object p1

    invoke-static {p1}, Landroidx/appcompat/view/menu/e01;->b(Landroidx/appcompat/view/menu/jh;)Ljava/lang/Object;

    move-result-object p1

    iput-object p1, p0, Landroidx/appcompat/view/menu/am;->s:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public b()Landroidx/appcompat/view/menu/jh;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/am;->q:Landroidx/appcompat/view/menu/wg;

    invoke-interface {v0}, Landroidx/appcompat/view/menu/wg;->b()Landroidx/appcompat/view/menu/jh;

    move-result-object v0

    return-object v0
.end method

.method public c(Ljava/lang/Object;Ljava/lang/Throwable;)V
    .locals 1

    instance-of v0, p1, Landroidx/appcompat/view/menu/nd;

    if-eqz v0, :cond_0

    check-cast p1, Landroidx/appcompat/view/menu/nd;

    iget-object p1, p1, Landroidx/appcompat/view/menu/nd;->b:Landroidx/appcompat/view/menu/jw;

    invoke-interface {p1, p2}, Landroidx/appcompat/view/menu/jw;->i(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_0
    return-void
.end method

.method public d()Landroidx/appcompat/view/menu/wg;
    .locals 0

    return-object p0
.end method

.method public g()Landroidx/appcompat/view/menu/vh;
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/am;->q:Landroidx/appcompat/view/menu/wg;

    instance-of v1, v0, Landroidx/appcompat/view/menu/vh;

    if-eqz v1, :cond_0

    check-cast v0, Landroidx/appcompat/view/menu/vh;

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    return-object v0
.end method

.method public j()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/am;->r:Ljava/lang/Object;

    invoke-static {}, Landroidx/appcompat/view/menu/bm;->a()Landroidx/appcompat/view/menu/iy0;

    move-result-object v1

    iput-object v1, p0, Landroidx/appcompat/view/menu/am;->r:Ljava/lang/Object;

    return-object v0
.end method

.method public final k()V
    .locals 3

    sget-object v0, Landroidx/appcompat/view/menu/am;->t:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    :cond_0
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    sget-object v2, Landroidx/appcompat/view/menu/bm;->b:Landroidx/appcompat/view/menu/iy0;

    if-eq v1, v2, :cond_0

    return-void
.end method

.method public final l()Landroidx/appcompat/view/menu/x9;
    .locals 4

    sget-object v0, Landroidx/appcompat/view/menu/am;->t:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    :cond_0
    :goto_0
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    if-nez v1, :cond_1

    sget-object v0, Landroidx/appcompat/view/menu/am;->t:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    sget-object v1, Landroidx/appcompat/view/menu/bm;->b:Landroidx/appcompat/view/menu/iy0;

    invoke-virtual {v0, p0, v1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    const/4 v0, 0x0

    return-object v0

    :cond_1
    instance-of v2, v1, Landroidx/appcompat/view/menu/x9;

    if-eqz v2, :cond_2

    sget-object v2, Landroidx/appcompat/view/menu/am;->t:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    sget-object v3, Landroidx/appcompat/view/menu/bm;->b:Landroidx/appcompat/view/menu/iy0;

    invoke-static {v2, p0, v1, v3}, Landroidx/appcompat/view/menu/q;->a(Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_0

    check-cast v1, Landroidx/appcompat/view/menu/x9;

    return-object v1

    :cond_2
    sget-object v2, Landroidx/appcompat/view/menu/bm;->b:Landroidx/appcompat/view/menu/iy0;

    if-eq v1, v2, :cond_0

    instance-of v2, v1, Ljava/lang/Throwable;

    if-eqz v2, :cond_3

    goto :goto_0

    :cond_3
    new-instance v0, Ljava/lang/IllegalStateException;

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "Inconsistent state "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final m()Landroidx/appcompat/view/menu/x9;
    .locals 2

    sget-object v0, Landroidx/appcompat/view/menu/am;->t:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    instance-of v1, v0, Landroidx/appcompat/view/menu/x9;

    if-eqz v1, :cond_0

    check-cast v0, Landroidx/appcompat/view/menu/x9;

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    return-object v0
.end method

.method public n(Ljava/lang/Object;)V
    .locals 6

    iget-object v0, p0, Landroidx/appcompat/view/menu/am;->q:Landroidx/appcompat/view/menu/wg;

    invoke-interface {v0}, Landroidx/appcompat/view/menu/wg;->b()Landroidx/appcompat/view/menu/jh;

    move-result-object v0

    const/4 v1, 0x0

    const/4 v2, 0x1

    invoke-static {p1, v1, v2, v1}, Landroidx/appcompat/view/menu/qd;->d(Ljava/lang/Object;Landroidx/appcompat/view/menu/jw;ILjava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    iget-object v4, p0, Landroidx/appcompat/view/menu/am;->p:Landroidx/appcompat/view/menu/mh;

    invoke-virtual {v4, v0}, Landroidx/appcompat/view/menu/mh;->D(Landroidx/appcompat/view/menu/jh;)Z

    move-result v4

    const/4 v5, 0x0

    if-eqz v4, :cond_0

    iput-object v3, p0, Landroidx/appcompat/view/menu/am;->r:Ljava/lang/Object;

    iput v5, p0, Landroidx/appcompat/view/menu/cm;->o:I

    iget-object p1, p0, Landroidx/appcompat/view/menu/am;->p:Landroidx/appcompat/view/menu/mh;

    invoke-virtual {p1, v0, p0}, Landroidx/appcompat/view/menu/mh;->A(Landroidx/appcompat/view/menu/jh;Ljava/lang/Runnable;)V

    goto :goto_2

    :cond_0
    sget-object v0, Landroidx/appcompat/view/menu/f01;->a:Landroidx/appcompat/view/menu/f01;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/f01;->a()Landroidx/appcompat/view/menu/ap;

    move-result-object v0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ap;->L()Z

    move-result v4

    if-eqz v4, :cond_1

    iput-object v3, p0, Landroidx/appcompat/view/menu/am;->r:Ljava/lang/Object;

    iput v5, p0, Landroidx/appcompat/view/menu/cm;->o:I

    invoke-virtual {v0, p0}, Landroidx/appcompat/view/menu/ap;->H(Landroidx/appcompat/view/menu/cm;)V

    goto :goto_2

    :cond_1
    invoke-virtual {v0, v2}, Landroidx/appcompat/view/menu/ap;->J(Z)V

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/am;->b()Landroidx/appcompat/view/menu/jh;

    move-result-object v3

    iget-object v4, p0, Landroidx/appcompat/view/menu/am;->s:Ljava/lang/Object;

    invoke-static {v3, v4}, Landroidx/appcompat/view/menu/e01;->c(Landroidx/appcompat/view/menu/jh;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v4
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :try_start_1
    iget-object v5, p0, Landroidx/appcompat/view/menu/am;->q:Landroidx/appcompat/view/menu/wg;

    invoke-interface {v5, p1}, Landroidx/appcompat/view/menu/wg;->n(Ljava/lang/Object;)V

    sget-object p1, Landroidx/appcompat/view/menu/n31;->a:Landroidx/appcompat/view/menu/n31;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    :try_start_2
    invoke-static {v3, v4}, Landroidx/appcompat/view/menu/e01;->a(Landroidx/appcompat/view/menu/jh;Ljava/lang/Object;)V

    :cond_2
    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ap;->N()Z

    move-result p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    if-nez p1, :cond_2

    :goto_0
    invoke-virtual {v0, v2}, Landroidx/appcompat/view/menu/ap;->F(Z)V

    goto :goto_2

    :catchall_0
    move-exception p1

    goto :goto_1

    :catchall_1
    move-exception p1

    :try_start_3
    invoke-static {v3, v4}, Landroidx/appcompat/view/menu/e01;->a(Landroidx/appcompat/view/menu/jh;Ljava/lang/Object;)V

    throw p1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    :goto_1
    :try_start_4
    invoke-virtual {p0, p1, v1}, Landroidx/appcompat/view/menu/cm;->i(Ljava/lang/Throwable;Ljava/lang/Throwable;)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    goto :goto_0

    :goto_2
    return-void

    :catchall_2
    move-exception p1

    invoke-virtual {v0, v2}, Landroidx/appcompat/view/menu/ap;->F(Z)V

    throw p1
.end method

.method public final o()Z
    .locals 1

    sget-object v0, Landroidx/appcompat/view/menu/am;->t:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    return v0
.end method

.method public final p(Ljava/lang/Throwable;)Z
    .locals 5

    sget-object v0, Landroidx/appcompat/view/menu/am;->t:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    :cond_0
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    sget-object v2, Landroidx/appcompat/view/menu/bm;->b:Landroidx/appcompat/view/menu/iy0;

    invoke-static {v1, v2}, Landroidx/appcompat/view/menu/x50;->a(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    const/4 v4, 0x1

    if-eqz v3, :cond_1

    sget-object v1, Landroidx/appcompat/view/menu/am;->t:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-static {v1, p0, v2, p1}, Landroidx/appcompat/view/menu/q;->a(Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    return v4

    :cond_1
    instance-of v2, v1, Ljava/lang/Throwable;

    if-eqz v2, :cond_2

    return v4

    :cond_2
    sget-object v2, Landroidx/appcompat/view/menu/am;->t:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    const/4 v3, 0x0

    invoke-static {v2, p0, v1, v3}, Landroidx/appcompat/view/menu/q;->a(Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    const/4 p1, 0x0

    return p1
.end method

.method public final q()V
    .locals 1

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/am;->k()V

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/am;->m()Landroidx/appcompat/view/menu/x9;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/x9;->r()V

    :cond_0
    return-void
.end method

.method public final r(Landroidx/appcompat/view/menu/w9;)Ljava/lang/Throwable;
    .locals 4

    sget-object v0, Landroidx/appcompat/view/menu/am;->t:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    :cond_0
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    sget-object v2, Landroidx/appcompat/view/menu/bm;->b:Landroidx/appcompat/view/menu/iy0;

    const/4 v3, 0x0

    if-ne v1, v2, :cond_1

    sget-object v1, Landroidx/appcompat/view/menu/am;->t:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-static {v1, p0, v2, p1}, Landroidx/appcompat/view/menu/q;->a(Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    return-object v3

    :cond_1
    instance-of p1, v1, Ljava/lang/Throwable;

    if-eqz p1, :cond_3

    sget-object p1, Landroidx/appcompat/view/menu/am;->t:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-static {p1, p0, v1, v3}, Landroidx/appcompat/view/menu/q;->a(Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_2

    check-cast v1, Ljava/lang/Throwable;

    return-object v1

    :cond_2
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Failed requirement."

    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_3
    new-instance p1, Ljava/lang/IllegalStateException;

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, "Inconsistent state "

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "DispatchedContinuation["

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Landroidx/appcompat/view/menu/am;->p:Landroidx/appcompat/view/menu/mh;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Landroidx/appcompat/view/menu/am;->q:Landroidx/appcompat/view/menu/wg;

    invoke-static {v1}, Landroidx/appcompat/view/menu/gj;->c(Landroidx/appcompat/view/menu/wg;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 v1, 0x5d

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
