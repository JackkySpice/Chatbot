.class public Lcom/google/firebase/messaging/FirebaseMessaging;
.super Ljava/lang/Object;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/firebase/messaging/FirebaseMessaging$a;
    }
.end annotation


# static fields
.field public static final n:J

.field public static o:Lcom/google/firebase/messaging/b;

.field public static p:Landroidx/appcompat/view/menu/a21;

.field public static q:Ljava/util/concurrent/ScheduledExecutorService;


# instance fields
.field public final a:Landroidx/appcompat/view/menu/sr;

.field public final b:Landroidx/appcompat/view/menu/fs;

.field public final c:Landroid/content/Context;

.field public final d:Landroidx/appcompat/view/menu/yx;

.field public final e:Lcom/google/firebase/messaging/a;

.field public final f:Lcom/google/firebase/messaging/FirebaseMessaging$a;

.field public final g:Ljava/util/concurrent/Executor;

.field public final h:Ljava/util/concurrent/Executor;

.field public final i:Ljava/util/concurrent/Executor;

.field public final j:Landroidx/appcompat/view/menu/vy0;

.field public final k:Landroidx/appcompat/view/menu/zc0;

.field public l:Z

.field public final m:Landroid/app/Application$ActivityLifecycleCallbacks;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    sget-object v0, Ljava/util/concurrent/TimeUnit;->HOURS:Ljava/util/concurrent/TimeUnit;

    const-wide/16 v1, 0x8

    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/TimeUnit;->toSeconds(J)J

    move-result-wide v0

    sput-wide v0, Lcom/google/firebase/messaging/FirebaseMessaging;->n:J

    return-void
.end method

.method public constructor <init>(Landroidx/appcompat/view/menu/sr;Landroidx/appcompat/view/menu/is;Landroidx/appcompat/view/menu/al0;Landroidx/appcompat/view/menu/al0;Landroidx/appcompat/view/menu/fs;Landroidx/appcompat/view/menu/a21;Landroidx/appcompat/view/menu/xx0;)V
    .locals 9

    .line 1
    new-instance v8, Landroidx/appcompat/view/menu/zc0;

    .line 2
    invoke-virtual {p1}, Landroidx/appcompat/view/menu/sr;->j()Landroid/content/Context;

    move-result-object v0

    invoke-direct {v8, v0}, Landroidx/appcompat/view/menu/zc0;-><init>(Landroid/content/Context;)V

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    move-object v4, p4

    move-object v5, p5

    move-object v6, p6

    move-object/from16 v7, p7

    .line 3
    invoke-direct/range {v0 .. v8}, Lcom/google/firebase/messaging/FirebaseMessaging;-><init>(Landroidx/appcompat/view/menu/sr;Landroidx/appcompat/view/menu/is;Landroidx/appcompat/view/menu/al0;Landroidx/appcompat/view/menu/al0;Landroidx/appcompat/view/menu/fs;Landroidx/appcompat/view/menu/a21;Landroidx/appcompat/view/menu/xx0;Landroidx/appcompat/view/menu/zc0;)V

    return-void
.end method

.method public constructor <init>(Landroidx/appcompat/view/menu/sr;Landroidx/appcompat/view/menu/is;Landroidx/appcompat/view/menu/al0;Landroidx/appcompat/view/menu/al0;Landroidx/appcompat/view/menu/fs;Landroidx/appcompat/view/menu/a21;Landroidx/appcompat/view/menu/xx0;Landroidx/appcompat/view/menu/zc0;)V
    .locals 11

    .line 4
    new-instance v7, Landroidx/appcompat/view/menu/yx;

    move-object v0, v7

    move-object v1, p1

    move-object/from16 v2, p8

    move-object v3, p3

    move-object v4, p4

    move-object/from16 v5, p5

    invoke-direct/range {v0 .. v5}, Landroidx/appcompat/view/menu/yx;-><init>(Landroidx/appcompat/view/menu/sr;Landroidx/appcompat/view/menu/zc0;Landroidx/appcompat/view/menu/al0;Landroidx/appcompat/view/menu/al0;Landroidx/appcompat/view/menu/fs;)V

    .line 5
    invoke-static {}, Landroidx/appcompat/view/menu/jr;->f()Ljava/util/concurrent/ExecutorService;

    move-result-object v8

    .line 6
    invoke-static {}, Landroidx/appcompat/view/menu/jr;->c()Ljava/util/concurrent/ScheduledExecutorService;

    move-result-object v9

    .line 7
    invoke-static {}, Landroidx/appcompat/view/menu/jr;->b()Ljava/util/concurrent/Executor;

    move-result-object v10

    move-object v0, p0

    move-object v2, p2

    move-object/from16 v3, p5

    move-object/from16 v4, p6

    move-object/from16 v5, p7

    move-object/from16 v6, p8

    .line 8
    invoke-direct/range {v0 .. v10}, Lcom/google/firebase/messaging/FirebaseMessaging;-><init>(Landroidx/appcompat/view/menu/sr;Landroidx/appcompat/view/menu/is;Landroidx/appcompat/view/menu/fs;Landroidx/appcompat/view/menu/a21;Landroidx/appcompat/view/menu/xx0;Landroidx/appcompat/view/menu/zc0;Landroidx/appcompat/view/menu/yx;Ljava/util/concurrent/Executor;Ljava/util/concurrent/Executor;Ljava/util/concurrent/Executor;)V

    return-void
.end method

.method public constructor <init>(Landroidx/appcompat/view/menu/sr;Landroidx/appcompat/view/menu/is;Landroidx/appcompat/view/menu/fs;Landroidx/appcompat/view/menu/a21;Landroidx/appcompat/view/menu/xx0;Landroidx/appcompat/view/menu/zc0;Landroidx/appcompat/view/menu/yx;Ljava/util/concurrent/Executor;Ljava/util/concurrent/Executor;Ljava/util/concurrent/Executor;)V
    .locals 1

    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    iput-boolean v0, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->l:Z

    sput-object p4, Lcom/google/firebase/messaging/FirebaseMessaging;->p:Landroidx/appcompat/view/menu/a21;

    iput-object p1, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->a:Landroidx/appcompat/view/menu/sr;

    iput-object p3, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->b:Landroidx/appcompat/view/menu/fs;

    .line 10
    new-instance p3, Lcom/google/firebase/messaging/FirebaseMessaging$a;

    invoke-direct {p3, p0, p5}, Lcom/google/firebase/messaging/FirebaseMessaging$a;-><init>(Lcom/google/firebase/messaging/FirebaseMessaging;Landroidx/appcompat/view/menu/xx0;)V

    iput-object p3, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->f:Lcom/google/firebase/messaging/FirebaseMessaging$a;

    .line 11
    invoke-virtual {p1}, Landroidx/appcompat/view/menu/sr;->j()Landroid/content/Context;

    move-result-object p3

    iput-object p3, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->c:Landroid/content/Context;

    .line 12
    new-instance p4, Landroidx/appcompat/view/menu/kr;

    invoke-direct {p4}, Landroidx/appcompat/view/menu/kr;-><init>()V

    iput-object p4, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->m:Landroid/app/Application$ActivityLifecycleCallbacks;

    iput-object p6, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->k:Landroidx/appcompat/view/menu/zc0;

    iput-object p8, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->h:Ljava/util/concurrent/Executor;

    iput-object p7, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->d:Landroidx/appcompat/view/menu/yx;

    .line 13
    new-instance p5, Lcom/google/firebase/messaging/a;

    invoke-direct {p5, p8}, Lcom/google/firebase/messaging/a;-><init>(Ljava/util/concurrent/Executor;)V

    iput-object p5, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->e:Lcom/google/firebase/messaging/a;

    iput-object p9, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->g:Ljava/util/concurrent/Executor;

    iput-object p10, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->i:Ljava/util/concurrent/Executor;

    .line 14
    invoke-virtual {p1}, Landroidx/appcompat/view/menu/sr;->j()Landroid/content/Context;

    move-result-object p1

    .line 15
    instance-of p5, p1, Landroid/app/Application;

    if-eqz p5, :cond_0

    .line 16
    check-cast p1, Landroid/app/Application;

    .line 17
    invoke-virtual {p1, p4}, Landroid/app/Application;->registerActivityLifecycleCallbacks(Landroid/app/Application$ActivityLifecycleCallbacks;)V

    goto :goto_0

    .line 18
    :cond_0
    new-instance p4, Ljava/lang/StringBuilder;

    invoke-direct {p4}, Ljava/lang/StringBuilder;-><init>()V

    const-string p5, "Context "

    invoke-virtual {p4, p5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p4, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p1, " was not an application, can\'t register for lifecycle callbacks. Some notification events may be dropped as a result."

    invoke-virtual {p4, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    :goto_0
    if-eqz p2, :cond_1

    .line 19
    new-instance p1, Landroidx/appcompat/view/menu/js;

    invoke-direct {p1, p0}, Landroidx/appcompat/view/menu/js;-><init>(Lcom/google/firebase/messaging/FirebaseMessaging;)V

    invoke-interface {p2, p1}, Landroidx/appcompat/view/menu/is;->a(Landroidx/appcompat/view/menu/is$a;)V

    .line 20
    :cond_1
    new-instance p1, Landroidx/appcompat/view/menu/ks;

    invoke-direct {p1, p0}, Landroidx/appcompat/view/menu/ks;-><init>(Lcom/google/firebase/messaging/FirebaseMessaging;)V

    invoke-interface {p9, p1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 21
    invoke-static {}, Landroidx/appcompat/view/menu/jr;->g()Ljava/util/concurrent/ScheduledExecutorService;

    move-result-object p1

    .line 22
    invoke-static {p0, p6, p7, p3, p1}, Landroidx/appcompat/view/menu/f11;->e(Lcom/google/firebase/messaging/FirebaseMessaging;Landroidx/appcompat/view/menu/zc0;Landroidx/appcompat/view/menu/yx;Landroid/content/Context;Ljava/util/concurrent/ScheduledExecutorService;)Landroidx/appcompat/view/menu/vy0;

    move-result-object p1

    iput-object p1, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->j:Landroidx/appcompat/view/menu/vy0;

    .line 23
    new-instance p2, Landroidx/appcompat/view/menu/ls;

    invoke-direct {p2, p0}, Landroidx/appcompat/view/menu/ls;-><init>(Lcom/google/firebase/messaging/FirebaseMessaging;)V

    invoke-virtual {p1, p9, p2}, Landroidx/appcompat/view/menu/vy0;->e(Ljava/util/concurrent/Executor;Landroidx/appcompat/view/menu/ig0;)Landroidx/appcompat/view/menu/vy0;

    .line 24
    new-instance p1, Landroidx/appcompat/view/menu/ms;

    invoke-direct {p1, p0}, Landroidx/appcompat/view/menu/ms;-><init>(Lcom/google/firebase/messaging/FirebaseMessaging;)V

    invoke-interface {p9, p1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-void
.end method

.method public static synthetic a(Lcom/google/firebase/messaging/FirebaseMessaging;Ljava/lang/String;Lcom/google/firebase/messaging/b$a;)Landroidx/appcompat/view/menu/vy0;
    .locals 0

    invoke-virtual {p0, p1, p2}, Lcom/google/firebase/messaging/FirebaseMessaging;->u(Ljava/lang/String;Lcom/google/firebase/messaging/b$a;)Landroidx/appcompat/view/menu/vy0;

    move-result-object p0

    return-object p0
.end method

.method public static synthetic b(Lcom/google/firebase/messaging/FirebaseMessaging;Ljava/lang/String;Lcom/google/firebase/messaging/b$a;Ljava/lang/String;)Landroidx/appcompat/view/menu/vy0;
    .locals 0

    invoke-virtual {p0, p1, p2, p3}, Lcom/google/firebase/messaging/FirebaseMessaging;->v(Ljava/lang/String;Lcom/google/firebase/messaging/b$a;Ljava/lang/String;)Landroidx/appcompat/view/menu/vy0;

    move-result-object p0

    return-object p0
.end method

.method public static synthetic c(Lcom/google/firebase/messaging/FirebaseMessaging;)V
    .locals 0

    invoke-virtual {p0}, Lcom/google/firebase/messaging/FirebaseMessaging;->z()V

    return-void
.end method

.method public static synthetic d(Lcom/google/firebase/messaging/FirebaseMessaging;Landroidx/appcompat/view/menu/f11;)V
    .locals 0

    invoke-virtual {p0, p1}, Lcom/google/firebase/messaging/FirebaseMessaging;->y(Landroidx/appcompat/view/menu/f11;)V

    return-void
.end method

.method public static synthetic e(Lcom/google/firebase/messaging/FirebaseMessaging;)V
    .locals 0

    invoke-virtual {p0}, Lcom/google/firebase/messaging/FirebaseMessaging;->x()V

    return-void
.end method

.method public static synthetic f(Lcom/google/firebase/messaging/FirebaseMessaging;Landroidx/appcompat/view/menu/xy0;)V
    .locals 0

    invoke-virtual {p0, p1}, Lcom/google/firebase/messaging/FirebaseMessaging;->w(Landroidx/appcompat/view/menu/xy0;)V

    return-void
.end method

.method public static synthetic g(Lcom/google/firebase/messaging/FirebaseMessaging;)Landroidx/appcompat/view/menu/sr;
    .locals 0

    iget-object p0, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->a:Landroidx/appcompat/view/menu/sr;

    return-object p0
.end method

.method public static declared-synchronized getInstance(Landroidx/appcompat/view/menu/sr;)Lcom/google/firebase/messaging/FirebaseMessaging;
    .locals 2
    .annotation build Landroidx/annotation/Keep;
    .end annotation

    const-class v0, Lcom/google/firebase/messaging/FirebaseMessaging;

    monitor-enter v0

    :try_start_0
    const-class v1, Lcom/google/firebase/messaging/FirebaseMessaging;

    invoke-virtual {p0, v1}, Landroidx/appcompat/view/menu/sr;->i(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Lcom/google/firebase/messaging/FirebaseMessaging;

    const-string v1, "Firebase Messaging component is not present"

    invoke-static {p0, v1}, Landroidx/appcompat/view/menu/ij0;->j(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v0

    return-object p0

    :catchall_0
    move-exception p0

    monitor-exit v0

    throw p0
.end method

.method public static synthetic h(Lcom/google/firebase/messaging/FirebaseMessaging;)V
    .locals 0

    invoke-virtual {p0}, Lcom/google/firebase/messaging/FirebaseMessaging;->D()V

    return-void
.end method

.method public static declared-synchronized l()Lcom/google/firebase/messaging/FirebaseMessaging;
    .locals 2

    const-class v0, Lcom/google/firebase/messaging/FirebaseMessaging;

    monitor-enter v0

    :try_start_0
    invoke-static {}, Landroidx/appcompat/view/menu/sr;->k()Landroidx/appcompat/view/menu/sr;

    move-result-object v1

    invoke-static {v1}, Lcom/google/firebase/messaging/FirebaseMessaging;->getInstance(Landroidx/appcompat/view/menu/sr;)Lcom/google/firebase/messaging/FirebaseMessaging;

    move-result-object v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v0

    return-object v1

    :catchall_0
    move-exception v1

    monitor-exit v0

    throw v1
.end method

.method public static declared-synchronized m(Landroid/content/Context;)Lcom/google/firebase/messaging/b;
    .locals 2

    const-class v0, Lcom/google/firebase/messaging/FirebaseMessaging;

    monitor-enter v0

    :try_start_0
    sget-object v1, Lcom/google/firebase/messaging/FirebaseMessaging;->o:Lcom/google/firebase/messaging/b;

    if-nez v1, :cond_0

    new-instance v1, Lcom/google/firebase/messaging/b;

    invoke-direct {v1, p0}, Lcom/google/firebase/messaging/b;-><init>(Landroid/content/Context;)V

    sput-object v1, Lcom/google/firebase/messaging/FirebaseMessaging;->o:Lcom/google/firebase/messaging/b;

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    :cond_0
    :goto_0
    sget-object p0, Lcom/google/firebase/messaging/FirebaseMessaging;->o:Lcom/google/firebase/messaging/b;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v0

    return-object p0

    :goto_1
    monitor-exit v0

    throw p0
.end method

.method public static q()Landroidx/appcompat/view/menu/a21;
    .locals 1

    sget-object v0, Lcom/google/firebase/messaging/FirebaseMessaging;->p:Landroidx/appcompat/view/menu/a21;

    return-object v0
.end method


# virtual methods
.method public A(Z)V
    .locals 1

    iget-object v0, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->f:Lcom/google/firebase/messaging/FirebaseMessaging$a;

    invoke-virtual {v0, p1}, Lcom/google/firebase/messaging/FirebaseMessaging$a;->f(Z)V

    return-void
.end method

.method public declared-synchronized B(Z)V
    .locals 0

    monitor-enter p0

    :try_start_0
    iput-boolean p1, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->l:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit p0

    return-void

    :catchall_0
    move-exception p1

    monitor-exit p0

    throw p1
.end method

.method public final declared-synchronized C()V
    .locals 2

    monitor-enter p0

    :try_start_0
    iget-boolean v0, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->l:Z

    if-nez v0, :cond_0

    const-wide/16 v0, 0x0

    invoke-virtual {p0, v0, v1}, Lcom/google/firebase/messaging/FirebaseMessaging;->E(J)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception v0

    goto :goto_1

    :cond_0
    :goto_0
    monitor-exit p0

    return-void

    :goto_1
    monitor-exit p0

    throw v0
.end method

.method public final D()V
    .locals 1

    invoke-virtual {p0}, Lcom/google/firebase/messaging/FirebaseMessaging;->p()Lcom/google/firebase/messaging/b$a;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/firebase/messaging/FirebaseMessaging;->F(Lcom/google/firebase/messaging/b$a;)Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p0}, Lcom/google/firebase/messaging/FirebaseMessaging;->C()V

    :cond_0
    return-void
.end method

.method public declared-synchronized E(J)V
    .locals 4

    monitor-enter p0

    const-wide/16 v0, 0x2

    mul-long/2addr v0, p1

    const-wide/16 v2, 0x1e

    :try_start_0
    invoke-static {v2, v3, v0, v1}, Ljava/lang/Math;->max(JJ)J

    move-result-wide v0

    sget-wide v2, Lcom/google/firebase/messaging/FirebaseMessaging;->n:J

    invoke-static {v0, v1, v2, v3}, Ljava/lang/Math;->min(JJ)J

    move-result-wide v0

    new-instance v2, Landroidx/appcompat/view/menu/jy0;

    invoke-direct {v2, p0, v0, v1}, Landroidx/appcompat/view/menu/jy0;-><init>(Lcom/google/firebase/messaging/FirebaseMessaging;J)V

    invoke-virtual {p0, v2, p1, p2}, Lcom/google/firebase/messaging/FirebaseMessaging;->j(Ljava/lang/Runnable;J)V

    const/4 p1, 0x1

    iput-boolean p1, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->l:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit p0

    return-void

    :catchall_0
    move-exception p1

    monitor-exit p0

    throw p1
.end method

.method public F(Lcom/google/firebase/messaging/b$a;)Z
    .locals 1

    if-eqz p1, :cond_1

    iget-object v0, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->k:Landroidx/appcompat/view/menu/zc0;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/zc0;->a()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, v0}, Lcom/google/firebase/messaging/b$a;->b(Ljava/lang/String;)Z

    move-result p1

    if-eqz p1, :cond_0

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    goto :goto_1

    :cond_1
    :goto_0
    const/4 p1, 0x1

    :goto_1
    return p1
.end method

.method public i()Ljava/lang/String;
    .locals 4

    invoke-virtual {p0}, Lcom/google/firebase/messaging/FirebaseMessaging;->p()Lcom/google/firebase/messaging/b$a;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/firebase/messaging/FirebaseMessaging;->F(Lcom/google/firebase/messaging/b$a;)Z

    move-result v1

    if-nez v1, :cond_0

    iget-object v0, v0, Lcom/google/firebase/messaging/b$a;->a:Ljava/lang/String;

    return-object v0

    :cond_0
    iget-object v1, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->a:Landroidx/appcompat/view/menu/sr;

    invoke-static {v1}, Landroidx/appcompat/view/menu/zc0;->c(Landroidx/appcompat/view/menu/sr;)Ljava/lang/String;

    move-result-object v1

    iget-object v2, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->e:Lcom/google/firebase/messaging/a;

    new-instance v3, Landroidx/appcompat/view/menu/ns;

    invoke-direct {v3, p0, v1, v0}, Landroidx/appcompat/view/menu/ns;-><init>(Lcom/google/firebase/messaging/FirebaseMessaging;Ljava/lang/String;Lcom/google/firebase/messaging/b$a;)V

    invoke-virtual {v2, v1, v3}, Lcom/google/firebase/messaging/a;->b(Ljava/lang/String;Lcom/google/firebase/messaging/a$a;)Landroidx/appcompat/view/menu/vy0;

    move-result-object v0

    :try_start_0
    invoke-static {v0}, Landroidx/appcompat/view/menu/fz0;->a(Landroidx/appcompat/view/menu/vy0;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;
    :try_end_0
    .catch Ljava/util/concurrent/ExecutionException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0

    return-object v0

    :catch_0
    move-exception v0

    goto :goto_0

    :catch_1
    move-exception v0

    :goto_0
    new-instance v1, Ljava/io/IOException;

    invoke-direct {v1, v0}, Ljava/io/IOException;-><init>(Ljava/lang/Throwable;)V

    throw v1
.end method

.method public j(Ljava/lang/Runnable;J)V
    .locals 4

    const-class v0, Lcom/google/firebase/messaging/FirebaseMessaging;

    monitor-enter v0

    :try_start_0
    sget-object v1, Lcom/google/firebase/messaging/FirebaseMessaging;->q:Ljava/util/concurrent/ScheduledExecutorService;

    if-nez v1, :cond_0

    new-instance v1, Ljava/util/concurrent/ScheduledThreadPoolExecutor;

    new-instance v2, Landroidx/appcompat/view/menu/ie0;

    const-string v3, "TAG"

    invoke-direct {v2, v3}, Landroidx/appcompat/view/menu/ie0;-><init>(Ljava/lang/String;)V

    const/4 v3, 0x1

    invoke-direct {v1, v3, v2}, Ljava/util/concurrent/ScheduledThreadPoolExecutor;-><init>(ILjava/util/concurrent/ThreadFactory;)V

    sput-object v1, Lcom/google/firebase/messaging/FirebaseMessaging;->q:Ljava/util/concurrent/ScheduledExecutorService;

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_0
    :goto_0
    sget-object v1, Lcom/google/firebase/messaging/FirebaseMessaging;->q:Ljava/util/concurrent/ScheduledExecutorService;

    sget-object v2, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    invoke-interface {v1, p1, p2, p3, v2}, Ljava/util/concurrent/ScheduledExecutorService;->schedule(Ljava/lang/Runnable;JLjava/util/concurrent/TimeUnit;)Ljava/util/concurrent/ScheduledFuture;

    monitor-exit v0

    return-void

    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p1
.end method

.method public k()Landroid/content/Context;
    .locals 1

    iget-object v0, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->c:Landroid/content/Context;

    return-object v0
.end method

.method public final n()Ljava/lang/String;
    .locals 2

    iget-object v0, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->a:Landroidx/appcompat/view/menu/sr;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/sr;->l()Ljava/lang/String;

    move-result-object v0

    const-string v1, "[DEFAULT]"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const-string v0, ""

    goto :goto_0

    :cond_0
    iget-object v0, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->a:Landroidx/appcompat/view/menu/sr;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/sr;->n()Ljava/lang/String;

    move-result-object v0

    :goto_0
    return-object v0
.end method

.method public o()Landroidx/appcompat/view/menu/vy0;
    .locals 3

    new-instance v0, Landroidx/appcompat/view/menu/xy0;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/xy0;-><init>()V

    iget-object v1, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->g:Ljava/util/concurrent/Executor;

    new-instance v2, Landroidx/appcompat/view/menu/os;

    invoke-direct {v2, p0, v0}, Landroidx/appcompat/view/menu/os;-><init>(Lcom/google/firebase/messaging/FirebaseMessaging;Landroidx/appcompat/view/menu/xy0;)V

    invoke-interface {v1, v2}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/xy0;->a()Landroidx/appcompat/view/menu/vy0;

    move-result-object v0

    return-object v0
.end method

.method public p()Lcom/google/firebase/messaging/b$a;
    .locals 3

    iget-object v0, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->c:Landroid/content/Context;

    invoke-static {v0}, Lcom/google/firebase/messaging/FirebaseMessaging;->m(Landroid/content/Context;)Lcom/google/firebase/messaging/b;

    move-result-object v0

    invoke-virtual {p0}, Lcom/google/firebase/messaging/FirebaseMessaging;->n()Ljava/lang/String;

    move-result-object v1

    iget-object v2, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->a:Landroidx/appcompat/view/menu/sr;

    invoke-static {v2}, Landroidx/appcompat/view/menu/zc0;->c(Landroidx/appcompat/view/menu/sr;)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, v1, v2}, Lcom/google/firebase/messaging/b;->d(Ljava/lang/String;Ljava/lang/String;)Lcom/google/firebase/messaging/b$a;

    move-result-object v0

    return-object v0
.end method

.method public final r(Ljava/lang/String;)V
    .locals 2

    iget-object v0, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->a:Landroidx/appcompat/view/menu/sr;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/sr;->l()Ljava/lang/String;

    move-result-object v0

    const-string v1, "[DEFAULT]"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_1

    const-string v0, "FirebaseMessaging"

    const/4 v1, 0x3

    invoke-static {v0, v1}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    move-result v0

    if-eqz v0, :cond_0

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "Invoking onNewToken for app: "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->a:Landroidx/appcompat/view/menu/sr;

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/sr;->l()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    :cond_0
    new-instance v0, Landroid/content/Intent;

    const-string v1, "com.google.firebase.messaging.NEW_TOKEN"

    invoke-direct {v0, v1}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    const-string v1, "token"

    invoke-virtual {v0, v1, p1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    new-instance p1, Landroidx/appcompat/view/menu/ir;

    iget-object v1, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->c:Landroid/content/Context;

    invoke-direct {p1, v1}, Landroidx/appcompat/view/menu/ir;-><init>(Landroid/content/Context;)V

    invoke-virtual {p1, v0}, Landroidx/appcompat/view/menu/ir;->k(Landroid/content/Intent;)Landroidx/appcompat/view/menu/vy0;

    :cond_1
    return-void
.end method

.method public s()Z
    .locals 1

    iget-object v0, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->f:Lcom/google/firebase/messaging/FirebaseMessaging$a;

    invoke-virtual {v0}, Lcom/google/firebase/messaging/FirebaseMessaging$a;->c()Z

    move-result v0

    return v0
.end method

.method public t()Z
    .locals 1

    iget-object v0, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->k:Landroidx/appcompat/view/menu/zc0;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/zc0;->g()Z

    move-result v0

    return v0
.end method

.method public final synthetic u(Ljava/lang/String;Lcom/google/firebase/messaging/b$a;)Landroidx/appcompat/view/menu/vy0;
    .locals 3

    iget-object v0, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->d:Landroidx/appcompat/view/menu/yx;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/yx;->e()Landroidx/appcompat/view/menu/vy0;

    move-result-object v0

    iget-object v1, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->i:Ljava/util/concurrent/Executor;

    new-instance v2, Landroidx/appcompat/view/menu/ps;

    invoke-direct {v2, p0, p1, p2}, Landroidx/appcompat/view/menu/ps;-><init>(Lcom/google/firebase/messaging/FirebaseMessaging;Ljava/lang/String;Lcom/google/firebase/messaging/b$a;)V

    invoke-virtual {v0, v1, v2}, Landroidx/appcompat/view/menu/vy0;->n(Ljava/util/concurrent/Executor;Landroidx/appcompat/view/menu/yx0;)Landroidx/appcompat/view/menu/vy0;

    move-result-object p1

    return-object p1
.end method

.method public final synthetic v(Ljava/lang/String;Lcom/google/firebase/messaging/b$a;Ljava/lang/String;)Landroidx/appcompat/view/menu/vy0;
    .locals 3

    iget-object v0, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->c:Landroid/content/Context;

    invoke-static {v0}, Lcom/google/firebase/messaging/FirebaseMessaging;->m(Landroid/content/Context;)Lcom/google/firebase/messaging/b;

    move-result-object v0

    invoke-virtual {p0}, Lcom/google/firebase/messaging/FirebaseMessaging;->n()Ljava/lang/String;

    move-result-object v1

    iget-object v2, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->k:Landroidx/appcompat/view/menu/zc0;

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/zc0;->a()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, v1, p1, p3, v2}, Lcom/google/firebase/messaging/b;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    if-eqz p2, :cond_0

    iget-object p1, p2, Lcom/google/firebase/messaging/b$a;->a:Ljava/lang/String;

    invoke-virtual {p3, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-nez p1, :cond_1

    :cond_0
    invoke-virtual {p0, p3}, Lcom/google/firebase/messaging/FirebaseMessaging;->r(Ljava/lang/String;)V

    :cond_1
    invoke-static {p3}, Landroidx/appcompat/view/menu/fz0;->e(Ljava/lang/Object;)Landroidx/appcompat/view/menu/vy0;

    move-result-object p1

    return-object p1
.end method

.method public final synthetic w(Landroidx/appcompat/view/menu/xy0;)V
    .locals 1

    :try_start_0
    invoke-virtual {p0}, Lcom/google/firebase/messaging/FirebaseMessaging;->i()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, v0}, Landroidx/appcompat/view/menu/xy0;->c(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception v0

    invoke-virtual {p1, v0}, Landroidx/appcompat/view/menu/xy0;->b(Ljava/lang/Exception;)V

    :goto_0
    return-void
.end method

.method public final synthetic x()V
    .locals 1

    invoke-virtual {p0}, Lcom/google/firebase/messaging/FirebaseMessaging;->s()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p0}, Lcom/google/firebase/messaging/FirebaseMessaging;->D()V

    :cond_0
    return-void
.end method

.method public final synthetic y(Landroidx/appcompat/view/menu/f11;)V
    .locals 1

    invoke-virtual {p0}, Lcom/google/firebase/messaging/FirebaseMessaging;->s()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/f11;->o()V

    :cond_0
    return-void
.end method

.method public final synthetic z()V
    .locals 1

    iget-object v0, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->c:Landroid/content/Context;

    invoke-static {v0}, Landroidx/appcompat/view/menu/kl0;->c(Landroid/content/Context;)V

    return-void
.end method
