.class public final Landroidx/appcompat/view/menu/a90;
.super Landroidx/appcompat/view/menu/mh;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/rk;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroidx/appcompat/view/menu/a90$a;
    }
.end annotation


# static fields
.field public static final t:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;


# instance fields
.field public final o:Landroidx/appcompat/view/menu/mh;

.field public final p:I

.field public final synthetic q:Landroidx/appcompat/view/menu/rk;

.field public final r:Landroidx/appcompat/view/menu/z90;

.field private volatile runningWorkers:I

.field public final s:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    const-class v0, Landroidx/appcompat/view/menu/a90;

    const-string v1, "runningWorkers"

    invoke-static {v0, v1}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    move-result-object v0

    sput-object v0, Landroidx/appcompat/view/menu/a90;->t:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    return-void
.end method

.method public constructor <init>(Landroidx/appcompat/view/menu/mh;I)V
    .locals 0

    invoke-direct {p0}, Landroidx/appcompat/view/menu/mh;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/a90;->o:Landroidx/appcompat/view/menu/mh;

    iput p2, p0, Landroidx/appcompat/view/menu/a90;->p:I

    instance-of p2, p1, Landroidx/appcompat/view/menu/rk;

    if-eqz p2, :cond_0

    check-cast p1, Landroidx/appcompat/view/menu/rk;

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    if-nez p1, :cond_1

    invoke-static {}, Landroidx/appcompat/view/menu/mj;->a()Landroidx/appcompat/view/menu/rk;

    move-result-object p1

    :cond_1
    iput-object p1, p0, Landroidx/appcompat/view/menu/a90;->q:Landroidx/appcompat/view/menu/rk;

    new-instance p1, Landroidx/appcompat/view/menu/z90;

    const/4 p2, 0x0

    invoke-direct {p1, p2}, Landroidx/appcompat/view/menu/z90;-><init>(Z)V

    iput-object p1, p0, Landroidx/appcompat/view/menu/a90;->r:Landroidx/appcompat/view/menu/z90;

    new-instance p1, Ljava/lang/Object;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/a90;->s:Ljava/lang/Object;

    return-void
.end method

.method public static final synthetic F(Landroidx/appcompat/view/menu/a90;)Landroidx/appcompat/view/menu/mh;
    .locals 0

    iget-object p0, p0, Landroidx/appcompat/view/menu/a90;->o:Landroidx/appcompat/view/menu/mh;

    return-object p0
.end method

.method public static final synthetic G(Landroidx/appcompat/view/menu/a90;)Ljava/lang/Runnable;
    .locals 0

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/a90;->H()Ljava/lang/Runnable;

    move-result-object p0

    return-object p0
.end method


# virtual methods
.method public A(Landroidx/appcompat/view/menu/jh;Ljava/lang/Runnable;)V
    .locals 0

    iget-object p1, p0, Landroidx/appcompat/view/menu/a90;->r:Landroidx/appcompat/view/menu/z90;

    invoke-virtual {p1, p2}, Landroidx/appcompat/view/menu/z90;->a(Ljava/lang/Object;)Z

    sget-object p1, Landroidx/appcompat/view/menu/a90;->t:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    invoke-virtual {p1, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    move-result p1

    iget p2, p0, Landroidx/appcompat/view/menu/a90;->p:I

    if-ge p1, p2, :cond_1

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/a90;->I()Z

    move-result p1

    if-eqz p1, :cond_1

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/a90;->H()Ljava/lang/Runnable;

    move-result-object p1

    if-nez p1, :cond_0

    goto :goto_0

    :cond_0
    new-instance p2, Landroidx/appcompat/view/menu/a90$a;

    invoke-direct {p2, p0, p1}, Landroidx/appcompat/view/menu/a90$a;-><init>(Landroidx/appcompat/view/menu/a90;Ljava/lang/Runnable;)V

    iget-object p1, p0, Landroidx/appcompat/view/menu/a90;->o:Landroidx/appcompat/view/menu/mh;

    invoke-virtual {p1, p0, p2}, Landroidx/appcompat/view/menu/mh;->A(Landroidx/appcompat/view/menu/jh;Ljava/lang/Runnable;)V

    :cond_1
    :goto_0
    return-void
.end method

.method public final H()Ljava/lang/Runnable;
    .locals 3

    :goto_0
    iget-object v0, p0, Landroidx/appcompat/view/menu/a90;->r:Landroidx/appcompat/view/menu/z90;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/z90;->d()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Runnable;

    if-nez v0, :cond_1

    iget-object v0, p0, Landroidx/appcompat/view/menu/a90;->s:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    sget-object v1, Landroidx/appcompat/view/menu/a90;->t:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->decrementAndGet(Ljava/lang/Object;)I

    iget-object v2, p0, Landroidx/appcompat/view/menu/a90;->r:Landroidx/appcompat/view/menu/z90;

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/z90;->c()I

    move-result v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-nez v2, :cond_0

    monitor-exit v0

    const/4 v0, 0x0

    return-object v0

    :cond_0
    :try_start_1
    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->incrementAndGet(Ljava/lang/Object;)I
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    monitor-exit v0

    goto :goto_0

    :catchall_0
    move-exception v1

    monitor-exit v0

    throw v1

    :cond_1
    return-object v0
.end method

.method public final I()Z
    .locals 4

    iget-object v0, p0, Landroidx/appcompat/view/menu/a90;->s:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    sget-object v1, Landroidx/appcompat/view/menu/a90;->t:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    move-result v2

    iget v3, p0, Landroidx/appcompat/view/menu/a90;->p:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-lt v2, v3, :cond_0

    monitor-exit v0

    const/4 v0, 0x0

    return v0

    :cond_0
    :try_start_1
    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->incrementAndGet(Ljava/lang/Object;)I
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    monitor-exit v0

    const/4 v0, 0x1

    return v0

    :catchall_0
    move-exception v1

    monitor-exit v0

    throw v1
.end method
