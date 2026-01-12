.class public Landroidx/appcompat/view/menu/es;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/fs;


# static fields
.field public static final m:Ljava/lang/Object;

.field public static final n:Ljava/util/concurrent/ThreadFactory;


# instance fields
.field public final a:Landroidx/appcompat/view/menu/sr;

.field public final b:Landroidx/appcompat/view/menu/zr;

.field public final c:Landroidx/appcompat/view/menu/vh0;

.field public final d:Landroidx/appcompat/view/menu/p41;

.field public final e:Landroidx/appcompat/view/menu/g80;

.field public final f:Landroidx/appcompat/view/menu/nn0;

.field public final g:Ljava/lang/Object;

.field public final h:Ljava/util/concurrent/ExecutorService;

.field public final i:Ljava/util/concurrent/Executor;

.field public j:Ljava/lang/String;

.field public k:Ljava/util/Set;

.field public final l:Ljava/util/List;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Ljava/lang/Object;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Landroidx/appcompat/view/menu/es;->m:Ljava/lang/Object;

    new-instance v0, Landroidx/appcompat/view/menu/es$a;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/es$a;-><init>()V

    sput-object v0, Landroidx/appcompat/view/menu/es;->n:Ljava/util/concurrent/ThreadFactory;

    return-void
.end method

.method public constructor <init>(Landroidx/appcompat/view/menu/sr;Landroidx/appcompat/view/menu/al0;Ljava/util/concurrent/ExecutorService;Ljava/util/concurrent/Executor;)V
    .locals 9

    .line 1
    new-instance v4, Landroidx/appcompat/view/menu/zr;

    .line 2
    invoke-virtual {p1}, Landroidx/appcompat/view/menu/sr;->j()Landroid/content/Context;

    move-result-object v0

    invoke-direct {v4, v0, p2}, Landroidx/appcompat/view/menu/zr;-><init>(Landroid/content/Context;Landroidx/appcompat/view/menu/al0;)V

    new-instance v5, Landroidx/appcompat/view/menu/vh0;

    invoke-direct {v5, p1}, Landroidx/appcompat/view/menu/vh0;-><init>(Landroidx/appcompat/view/menu/sr;)V

    .line 3
    invoke-static {}, Landroidx/appcompat/view/menu/p41;->c()Landroidx/appcompat/view/menu/p41;

    move-result-object v6

    new-instance v7, Landroidx/appcompat/view/menu/g80;

    new-instance p2, Landroidx/appcompat/view/menu/bs;

    invoke-direct {p2, p1}, Landroidx/appcompat/view/menu/bs;-><init>(Landroidx/appcompat/view/menu/sr;)V

    invoke-direct {v7, p2}, Landroidx/appcompat/view/menu/g80;-><init>(Landroidx/appcompat/view/menu/al0;)V

    new-instance v8, Landroidx/appcompat/view/menu/nn0;

    invoke-direct {v8}, Landroidx/appcompat/view/menu/nn0;-><init>()V

    move-object v0, p0

    move-object v1, p3

    move-object v2, p4

    move-object v3, p1

    .line 4
    invoke-direct/range {v0 .. v8}, Landroidx/appcompat/view/menu/es;-><init>(Ljava/util/concurrent/ExecutorService;Ljava/util/concurrent/Executor;Landroidx/appcompat/view/menu/sr;Landroidx/appcompat/view/menu/zr;Landroidx/appcompat/view/menu/vh0;Landroidx/appcompat/view/menu/p41;Landroidx/appcompat/view/menu/g80;Landroidx/appcompat/view/menu/nn0;)V

    return-void
.end method

.method public constructor <init>(Ljava/util/concurrent/ExecutorService;Ljava/util/concurrent/Executor;Landroidx/appcompat/view/menu/sr;Landroidx/appcompat/view/menu/zr;Landroidx/appcompat/view/menu/vh0;Landroidx/appcompat/view/menu/p41;Landroidx/appcompat/view/menu/g80;Landroidx/appcompat/view/menu/nn0;)V
    .locals 1

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    new-instance v0, Ljava/lang/Object;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iput-object v0, p0, Landroidx/appcompat/view/menu/es;->g:Ljava/lang/Object;

    .line 7
    new-instance v0, Ljava/util/HashSet;

    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    iput-object v0, p0, Landroidx/appcompat/view/menu/es;->k:Ljava/util/Set;

    .line 8
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Landroidx/appcompat/view/menu/es;->l:Ljava/util/List;

    iput-object p3, p0, Landroidx/appcompat/view/menu/es;->a:Landroidx/appcompat/view/menu/sr;

    iput-object p4, p0, Landroidx/appcompat/view/menu/es;->b:Landroidx/appcompat/view/menu/zr;

    iput-object p5, p0, Landroidx/appcompat/view/menu/es;->c:Landroidx/appcompat/view/menu/vh0;

    iput-object p6, p0, Landroidx/appcompat/view/menu/es;->d:Landroidx/appcompat/view/menu/p41;

    iput-object p7, p0, Landroidx/appcompat/view/menu/es;->e:Landroidx/appcompat/view/menu/g80;

    iput-object p8, p0, Landroidx/appcompat/view/menu/es;->f:Landroidx/appcompat/view/menu/nn0;

    iput-object p1, p0, Landroidx/appcompat/view/menu/es;->h:Ljava/util/concurrent/ExecutorService;

    iput-object p2, p0, Landroidx/appcompat/view/menu/es;->i:Ljava/util/concurrent/Executor;

    return-void
.end method

.method public static synthetic c(Landroidx/appcompat/view/menu/sr;)Landroidx/appcompat/view/menu/g40;
    .locals 0

    invoke-static {p0}, Landroidx/appcompat/view/menu/es;->z(Landroidx/appcompat/view/menu/sr;)Landroidx/appcompat/view/menu/g40;

    move-result-object p0

    return-object p0
.end method

.method public static synthetic d(Landroidx/appcompat/view/menu/es;)V
    .locals 0

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/es;->x()V

    return-void
.end method

.method public static synthetic e(Landroidx/appcompat/view/menu/es;Z)V
    .locals 0

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/es;->w(Z)V

    return-void
.end method

.method public static synthetic f(Landroidx/appcompat/view/menu/es;Z)V
    .locals 0

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/es;->y(Z)V

    return-void
.end method

.method public static q()Landroidx/appcompat/view/menu/es;
    .locals 1

    invoke-static {}, Landroidx/appcompat/view/menu/sr;->k()Landroidx/appcompat/view/menu/sr;

    move-result-object v0

    invoke-static {v0}, Landroidx/appcompat/view/menu/es;->r(Landroidx/appcompat/view/menu/sr;)Landroidx/appcompat/view/menu/es;

    move-result-object v0

    return-object v0
.end method

.method public static r(Landroidx/appcompat/view/menu/sr;)Landroidx/appcompat/view/menu/es;
    .locals 2

    if-eqz p0, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    const-string v1, "Null is not a valid value of FirebaseApp."

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/ij0;->b(ZLjava/lang/Object;)V

    const-class v0, Landroidx/appcompat/view/menu/fs;

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/sr;->i(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Landroidx/appcompat/view/menu/es;

    return-object p0
.end method

.method public static synthetic z(Landroidx/appcompat/view/menu/sr;)Landroidx/appcompat/view/menu/g40;
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/g40;

    invoke-direct {v0, p0}, Landroidx/appcompat/view/menu/g40;-><init>(Landroidx/appcompat/view/menu/sr;)V

    return-object v0
.end method


# virtual methods
.method public final A()V
    .locals 3

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/es;->n()Ljava/lang/String;

    move-result-object v0

    const-string v1, "Please set your Application ID. A valid Firebase App ID is required to communicate with Firebase server APIs: It identifies your application with Firebase.Please refer to https://firebase.google.com/support/privacy/init-options."

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/ij0;->f(Ljava/lang/String;Ljava/lang/Object;)Ljava/lang/String;

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/es;->u()Ljava/lang/String;

    move-result-object v0

    const-string v2, "Please set your Project ID. A valid Firebase Project ID is required to communicate with Firebase server APIs: It identifies your application with Firebase.Please refer to https://firebase.google.com/support/privacy/init-options."

    invoke-static {v0, v2}, Landroidx/appcompat/view/menu/ij0;->f(Ljava/lang/String;Ljava/lang/Object;)Ljava/lang/String;

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/es;->m()Ljava/lang/String;

    move-result-object v0

    const-string v2, "Please set a valid API key. A Firebase API key is required to communicate with Firebase server APIs: It authenticates your project with Google.Please refer to https://firebase.google.com/support/privacy/init-options."

    invoke-static {v0, v2}, Landroidx/appcompat/view/menu/ij0;->f(Ljava/lang/String;Ljava/lang/Object;)Ljava/lang/String;

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/es;->n()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Landroidx/appcompat/view/menu/p41;->h(Ljava/lang/String;)Z

    move-result v0

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/ij0;->b(ZLjava/lang/Object;)V

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/es;->m()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Landroidx/appcompat/view/menu/p41;->g(Ljava/lang/String;)Z

    move-result v0

    invoke-static {v0, v2}, Landroidx/appcompat/view/menu/ij0;->b(ZLjava/lang/Object;)V

    return-void
.end method

.method public final B(Landroidx/appcompat/view/menu/wh0;)Ljava/lang/String;
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/es;->a:Landroidx/appcompat/view/menu/sr;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/sr;->l()Ljava/lang/String;

    move-result-object v0

    const-string v1, "CHIME_ANDROID_SDK"

    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_0

    iget-object v0, p0, Landroidx/appcompat/view/menu/es;->a:Landroidx/appcompat/view/menu/sr;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/sr;->t()Z

    move-result v0

    if-eqz v0, :cond_1

    :cond_0
    invoke-virtual {p1}, Landroidx/appcompat/view/menu/wh0;->m()Z

    move-result p1

    if-nez p1, :cond_2

    :cond_1
    iget-object p1, p0, Landroidx/appcompat/view/menu/es;->f:Landroidx/appcompat/view/menu/nn0;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/nn0;->a()Ljava/lang/String;

    move-result-object p1

    return-object p1

    :cond_2
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/es;->p()Landroidx/appcompat/view/menu/g40;

    move-result-object p1

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/g40;->f()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v0

    if-eqz v0, :cond_3

    iget-object p1, p0, Landroidx/appcompat/view/menu/es;->f:Landroidx/appcompat/view/menu/nn0;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/nn0;->a()Ljava/lang/String;

    move-result-object p1

    :cond_3
    return-object p1
.end method

.method public final C(Landroidx/appcompat/view/menu/wh0;)Landroidx/appcompat/view/menu/wh0;
    .locals 10

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/wh0;->d()Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/wh0;->d()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->length()I

    move-result v0

    const/16 v1, 0xb

    if-ne v0, v1, :cond_0

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/es;->p()Landroidx/appcompat/view/menu/g40;

    move-result-object v0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/g40;->i()Ljava/lang/String;

    move-result-object v0

    :goto_0
    move-object v6, v0

    goto :goto_1

    :cond_0
    const/4 v0, 0x0

    goto :goto_0

    :goto_1
    iget-object v1, p0, Landroidx/appcompat/view/menu/es;->b:Landroidx/appcompat/view/menu/zr;

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/es;->m()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/wh0;->d()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/es;->u()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/es;->n()Ljava/lang/String;

    move-result-object v5

    invoke-virtual/range {v1 .. v6}, Landroidx/appcompat/view/menu/zr;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroidx/appcompat/view/menu/n50;

    move-result-object v0

    sget-object v1, Landroidx/appcompat/view/menu/es$b;->a:[I

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/n50;->e()Landroidx/appcompat/view/menu/n50$b;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    move-result v2

    aget v1, v1, v2

    const/4 v2, 0x1

    if-eq v1, v2, :cond_2

    const/4 v0, 0x2

    if-ne v1, v0, :cond_1

    const-string v0, "BAD CONFIG"

    invoke-virtual {p1, v0}, Landroidx/appcompat/view/menu/wh0;->q(Ljava/lang/String;)Landroidx/appcompat/view/menu/wh0;

    move-result-object p1

    return-object p1

    :cond_1
    new-instance p1, Landroidx/appcompat/view/menu/gs;

    const-string v0, "Firebase Installations Service is unavailable. Please try again later."

    sget-object v1, Landroidx/appcompat/view/menu/gs$a;->n:Landroidx/appcompat/view/menu/gs$a;

    invoke-direct {p1, v0, v1}, Landroidx/appcompat/view/menu/gs;-><init>(Ljava/lang/String;Landroidx/appcompat/view/menu/gs$a;)V

    throw p1

    :cond_2
    invoke-virtual {v0}, Landroidx/appcompat/view/menu/n50;->c()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/n50;->d()Ljava/lang/String;

    move-result-object v4

    iget-object v1, p0, Landroidx/appcompat/view/menu/es;->d:Landroidx/appcompat/view/menu/p41;

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/p41;->b()J

    move-result-wide v5

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/n50;->b()Landroidx/appcompat/view/menu/w01;

    move-result-object v1

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/w01;->c()Ljava/lang/String;

    move-result-object v7

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/n50;->b()Landroidx/appcompat/view/menu/w01;

    move-result-object v0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/w01;->d()J

    move-result-wide v8

    move-object v2, p1

    invoke-virtual/range {v2 .. v9}, Landroidx/appcompat/view/menu/wh0;->s(Ljava/lang/String;Ljava/lang/String;JLjava/lang/String;J)Landroidx/appcompat/view/menu/wh0;

    move-result-object p1

    return-object p1
.end method

.method public final D(Ljava/lang/Exception;)V
    .locals 3

    iget-object v0, p0, Landroidx/appcompat/view/menu/es;->g:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    iget-object v1, p0, Landroidx/appcompat/view/menu/es;->l:Ljava/util/List;

    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_0
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Landroidx/appcompat/view/menu/uw0;

    invoke-interface {v2, p1}, Landroidx/appcompat/view/menu/uw0;->b(Ljava/lang/Exception;)Z

    move-result v2

    if-eqz v2, :cond_0

    invoke-interface {v1}, Ljava/util/Iterator;->remove()V

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_1
    monitor-exit v0

    return-void

    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p1
.end method

.method public final E(Landroidx/appcompat/view/menu/wh0;)V
    .locals 3

    iget-object v0, p0, Landroidx/appcompat/view/menu/es;->g:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    iget-object v1, p0, Landroidx/appcompat/view/menu/es;->l:Ljava/util/List;

    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_0
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Landroidx/appcompat/view/menu/uw0;

    invoke-interface {v2, p1}, Landroidx/appcompat/view/menu/uw0;->a(Landroidx/appcompat/view/menu/wh0;)Z

    move-result v2

    if-eqz v2, :cond_0

    invoke-interface {v1}, Ljava/util/Iterator;->remove()V

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_1
    monitor-exit v0

    return-void

    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p1
.end method

.method public final declared-synchronized F(Ljava/lang/String;)V
    .locals 0

    monitor-enter p0

    :try_start_0
    iput-object p1, p0, Landroidx/appcompat/view/menu/es;->j:Ljava/lang/String;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit p0

    return-void

    :catchall_0
    move-exception p1

    monitor-exit p0

    throw p1
.end method

.method public final declared-synchronized G(Landroidx/appcompat/view/menu/wh0;Landroidx/appcompat/view/menu/wh0;)V
    .locals 1

    monitor-enter p0

    :try_start_0
    iget-object v0, p0, Landroidx/appcompat/view/menu/es;->k:Ljava/util/Set;

    invoke-interface {v0}, Ljava/util/Set;->size()I

    move-result v0

    if-eqz v0, :cond_1

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/wh0;->d()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p2}, Landroidx/appcompat/view/menu/wh0;->d()Ljava/lang/String;

    move-result-object v0

    invoke-static {p1, v0}, Landroid/text/TextUtils;->equals(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Z

    move-result p1

    if-nez p1, :cond_1

    iget-object p1, p0, Landroidx/appcompat/view/menu/es;->k:Ljava/util/Set;

    invoke-interface {p1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p1

    invoke-static {p1}, Landroidx/appcompat/view/menu/fy0;->a(Ljava/lang/Object;)V

    invoke-virtual {p2}, Landroidx/appcompat/view/menu/wh0;->d()Ljava/lang/String;

    const/4 p1, 0x0

    throw p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_1
    :goto_0
    monitor-exit p0

    return-void

    :goto_1
    monitor-exit p0

    throw p1
.end method

.method public a()Landroidx/appcompat/view/menu/vy0;
    .locals 3

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/es;->A()V

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/es;->o()Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-static {v0}, Landroidx/appcompat/view/menu/fz0;->e(Ljava/lang/Object;)Landroidx/appcompat/view/menu/vy0;

    move-result-object v0

    return-object v0

    :cond_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/es;->h()Landroidx/appcompat/view/menu/vy0;

    move-result-object v0

    iget-object v1, p0, Landroidx/appcompat/view/menu/es;->h:Ljava/util/concurrent/ExecutorService;

    new-instance v2, Landroidx/appcompat/view/menu/as;

    invoke-direct {v2, p0}, Landroidx/appcompat/view/menu/as;-><init>(Landroidx/appcompat/view/menu/es;)V

    invoke-interface {v1, v2}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-object v0
.end method

.method public b(Z)Landroidx/appcompat/view/menu/vy0;
    .locals 3

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/es;->A()V

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/es;->g()Landroidx/appcompat/view/menu/vy0;

    move-result-object v0

    iget-object v1, p0, Landroidx/appcompat/view/menu/es;->h:Ljava/util/concurrent/ExecutorService;

    new-instance v2, Landroidx/appcompat/view/menu/ds;

    invoke-direct {v2, p0, p1}, Landroidx/appcompat/view/menu/ds;-><init>(Landroidx/appcompat/view/menu/es;Z)V

    invoke-interface {v1, v2}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-object v0
.end method

.method public final g()Landroidx/appcompat/view/menu/vy0;
    .locals 3

    new-instance v0, Landroidx/appcompat/view/menu/xy0;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/xy0;-><init>()V

    new-instance v1, Landroidx/appcompat/view/menu/ox;

    iget-object v2, p0, Landroidx/appcompat/view/menu/es;->d:Landroidx/appcompat/view/menu/p41;

    invoke-direct {v1, v2, v0}, Landroidx/appcompat/view/menu/ox;-><init>(Landroidx/appcompat/view/menu/p41;Landroidx/appcompat/view/menu/xy0;)V

    invoke-virtual {p0, v1}, Landroidx/appcompat/view/menu/es;->i(Landroidx/appcompat/view/menu/uw0;)V

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/xy0;->a()Landroidx/appcompat/view/menu/vy0;

    move-result-object v0

    return-object v0
.end method

.method public final h()Landroidx/appcompat/view/menu/vy0;
    .locals 2

    new-instance v0, Landroidx/appcompat/view/menu/xy0;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/xy0;-><init>()V

    new-instance v1, Landroidx/appcompat/view/menu/px;

    invoke-direct {v1, v0}, Landroidx/appcompat/view/menu/px;-><init>(Landroidx/appcompat/view/menu/xy0;)V

    invoke-virtual {p0, v1}, Landroidx/appcompat/view/menu/es;->i(Landroidx/appcompat/view/menu/uw0;)V

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/xy0;->a()Landroidx/appcompat/view/menu/vy0;

    move-result-object v0

    return-object v0
.end method

.method public final i(Landroidx/appcompat/view/menu/uw0;)V
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/es;->g:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    iget-object v1, p0, Landroidx/appcompat/view/menu/es;->l:Ljava/util/List;

    invoke-interface {v1, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    monitor-exit v0

    return-void

    :catchall_0
    move-exception p1

    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p1
.end method

.method public final j(Z)V
    .locals 2

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/es;->s()Landroidx/appcompat/view/menu/wh0;

    move-result-object v0

    :try_start_0
    invoke-virtual {v0}, Landroidx/appcompat/view/menu/wh0;->i()Z

    move-result v1

    if-nez v1, :cond_3

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/wh0;->l()Z

    move-result v1

    if-eqz v1, :cond_0

    goto :goto_1

    :cond_0
    if-nez p1, :cond_2

    iget-object p1, p0, Landroidx/appcompat/view/menu/es;->d:Landroidx/appcompat/view/menu/p41;

    invoke-virtual {p1, v0}, Landroidx/appcompat/view/menu/p41;->f(Landroidx/appcompat/view/menu/wh0;)Z

    move-result p1

    if-eqz p1, :cond_1

    goto :goto_0

    :cond_1
    return-void

    :catch_0
    move-exception p1

    goto :goto_4

    :cond_2
    :goto_0
    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/es;->l(Landroidx/appcompat/view/menu/wh0;)Landroidx/appcompat/view/menu/wh0;

    move-result-object p1

    goto :goto_2

    :cond_3
    :goto_1
    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/es;->C(Landroidx/appcompat/view/menu/wh0;)Landroidx/appcompat/view/menu/wh0;

    move-result-object p1
    :try_end_0
    .catch Landroidx/appcompat/view/menu/gs; {:try_start_0 .. :try_end_0} :catch_0

    :goto_2
    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/es;->v(Landroidx/appcompat/view/menu/wh0;)V

    invoke-virtual {p0, v0, p1}, Landroidx/appcompat/view/menu/es;->G(Landroidx/appcompat/view/menu/wh0;Landroidx/appcompat/view/menu/wh0;)V

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/wh0;->k()Z

    move-result v0

    if-eqz v0, :cond_4

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/wh0;->d()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/es;->F(Ljava/lang/String;)V

    :cond_4
    invoke-virtual {p1}, Landroidx/appcompat/view/menu/wh0;->i()Z

    move-result v0

    if-eqz v0, :cond_5

    new-instance p1, Landroidx/appcompat/view/menu/gs;

    sget-object v0, Landroidx/appcompat/view/menu/gs$a;->m:Landroidx/appcompat/view/menu/gs$a;

    invoke-direct {p1, v0}, Landroidx/appcompat/view/menu/gs;-><init>(Landroidx/appcompat/view/menu/gs$a;)V

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/es;->D(Ljava/lang/Exception;)V

    goto :goto_3

    :cond_5
    invoke-virtual {p1}, Landroidx/appcompat/view/menu/wh0;->j()Z

    move-result v0

    if-eqz v0, :cond_6

    new-instance p1, Ljava/io/IOException;

    const-string v0, "Installation ID could not be validated with the Firebase servers (maybe it was deleted). Firebase Installations will need to create a new Installation ID and auth token. Please retry your last request."

    invoke-direct {p1, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/es;->D(Ljava/lang/Exception;)V

    goto :goto_3

    :cond_6
    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/es;->E(Landroidx/appcompat/view/menu/wh0;)V

    :goto_3
    return-void

    :goto_4
    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/es;->D(Ljava/lang/Exception;)V

    return-void
.end method

.method public final k(Z)V
    .locals 2

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/es;->t()Landroidx/appcompat/view/menu/wh0;

    move-result-object v0

    if-eqz p1, :cond_0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/wh0;->p()Landroidx/appcompat/view/menu/wh0;

    move-result-object v0

    :cond_0
    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/es;->E(Landroidx/appcompat/view/menu/wh0;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/es;->i:Ljava/util/concurrent/Executor;

    new-instance v1, Landroidx/appcompat/view/menu/cs;

    invoke-direct {v1, p0, p1}, Landroidx/appcompat/view/menu/cs;-><init>(Landroidx/appcompat/view/menu/es;Z)V

    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-void
.end method

.method public final l(Landroidx/appcompat/view/menu/wh0;)Landroidx/appcompat/view/menu/wh0;
    .locals 6

    iget-object v0, p0, Landroidx/appcompat/view/menu/es;->b:Landroidx/appcompat/view/menu/zr;

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/es;->m()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/wh0;->d()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/es;->u()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/wh0;->f()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v0, v1, v2, v3, v4}, Landroidx/appcompat/view/menu/zr;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroidx/appcompat/view/menu/w01;

    move-result-object v0

    sget-object v1, Landroidx/appcompat/view/menu/es$b;->b:[I

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/w01;->b()Landroidx/appcompat/view/menu/w01$b;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    move-result v2

    aget v1, v1, v2

    const/4 v2, 0x1

    if-eq v1, v2, :cond_2

    const/4 v0, 0x2

    if-eq v1, v0, :cond_1

    const/4 v0, 0x3

    if-ne v1, v0, :cond_0

    const/4 v0, 0x0

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/es;->F(Ljava/lang/String;)V

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/wh0;->r()Landroidx/appcompat/view/menu/wh0;

    move-result-object p1

    return-object p1

    :cond_0
    new-instance p1, Landroidx/appcompat/view/menu/gs;

    const-string v0, "Firebase Installations Service is unavailable. Please try again later."

    sget-object v1, Landroidx/appcompat/view/menu/gs$a;->n:Landroidx/appcompat/view/menu/gs$a;

    invoke-direct {p1, v0, v1}, Landroidx/appcompat/view/menu/gs;-><init>(Ljava/lang/String;Landroidx/appcompat/view/menu/gs$a;)V

    throw p1

    :cond_1
    const-string v0, "BAD CONFIG"

    invoke-virtual {p1, v0}, Landroidx/appcompat/view/menu/wh0;->q(Ljava/lang/String;)Landroidx/appcompat/view/menu/wh0;

    move-result-object p1

    return-object p1

    :cond_2
    invoke-virtual {v0}, Landroidx/appcompat/view/menu/w01;->c()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/w01;->d()J

    move-result-wide v2

    iget-object v0, p0, Landroidx/appcompat/view/menu/es;->d:Landroidx/appcompat/view/menu/p41;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/p41;->b()J

    move-result-wide v4

    move-object v0, p1

    invoke-virtual/range {v0 .. v5}, Landroidx/appcompat/view/menu/wh0;->o(Ljava/lang/String;JJ)Landroidx/appcompat/view/menu/wh0;

    move-result-object p1

    return-object p1
.end method

.method public m()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/es;->a:Landroidx/appcompat/view/menu/sr;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/sr;->m()Landroidx/appcompat/view/menu/ss;

    move-result-object v0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ss;->b()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public n()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/es;->a:Landroidx/appcompat/view/menu/sr;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/sr;->m()Landroidx/appcompat/view/menu/ss;

    move-result-object v0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ss;->c()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final declared-synchronized o()Ljava/lang/String;
    .locals 1

    monitor-enter p0

    :try_start_0
    iget-object v0, p0, Landroidx/appcompat/view/menu/es;->j:Ljava/lang/String;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit p0

    return-object v0

    :catchall_0
    move-exception v0

    monitor-exit p0

    throw v0
.end method

.method public final p()Landroidx/appcompat/view/menu/g40;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/es;->e:Landroidx/appcompat/view/menu/g80;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/g80;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/g40;

    return-object v0
.end method

.method public final s()Landroidx/appcompat/view/menu/wh0;
    .locals 3

    sget-object v0, Landroidx/appcompat/view/menu/es;->m:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    iget-object v1, p0, Landroidx/appcompat/view/menu/es;->a:Landroidx/appcompat/view/menu/sr;

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/sr;->j()Landroid/content/Context;

    move-result-object v1

    const-string v2, "generatefid.lock"

    invoke-static {v1, v2}, Landroidx/appcompat/view/menu/gi;->a(Landroid/content/Context;Ljava/lang/String;)Landroidx/appcompat/view/menu/gi;

    move-result-object v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :try_start_1
    iget-object v2, p0, Landroidx/appcompat/view/menu/es;->c:Landroidx/appcompat/view/menu/vh0;

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/vh0;->d()Landroidx/appcompat/view/menu/wh0;

    move-result-object v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    if-eqz v1, :cond_0

    :try_start_2
    invoke-virtual {v1}, Landroidx/appcompat/view/menu/gi;->b()V

    goto :goto_0

    :catchall_0
    move-exception v1

    goto :goto_1

    :cond_0
    :goto_0
    monitor-exit v0

    return-object v2

    :catchall_1
    move-exception v2

    if-eqz v1, :cond_1

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/gi;->b()V

    :cond_1
    throw v2

    :goto_1
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    throw v1
.end method

.method public final t()Landroidx/appcompat/view/menu/wh0;
    .locals 5

    sget-object v0, Landroidx/appcompat/view/menu/es;->m:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    iget-object v1, p0, Landroidx/appcompat/view/menu/es;->a:Landroidx/appcompat/view/menu/sr;

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/sr;->j()Landroid/content/Context;

    move-result-object v1

    const-string v2, "generatefid.lock"

    invoke-static {v1, v2}, Landroidx/appcompat/view/menu/gi;->a(Landroid/content/Context;Ljava/lang/String;)Landroidx/appcompat/view/menu/gi;

    move-result-object v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    :try_start_1
    iget-object v2, p0, Landroidx/appcompat/view/menu/es;->c:Landroidx/appcompat/view/menu/vh0;

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/vh0;->d()Landroidx/appcompat/view/menu/wh0;

    move-result-object v2

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/wh0;->j()Z

    move-result v3

    if-eqz v3, :cond_0

    invoke-virtual {p0, v2}, Landroidx/appcompat/view/menu/es;->B(Landroidx/appcompat/view/menu/wh0;)Ljava/lang/String;

    move-result-object v3

    iget-object v4, p0, Landroidx/appcompat/view/menu/es;->c:Landroidx/appcompat/view/menu/vh0;

    invoke-virtual {v2, v3}, Landroidx/appcompat/view/menu/wh0;->t(Ljava/lang/String;)Landroidx/appcompat/view/menu/wh0;

    move-result-object v2

    invoke-virtual {v4, v2}, Landroidx/appcompat/view/menu/vh0;->b(Landroidx/appcompat/view/menu/wh0;)Landroidx/appcompat/view/menu/wh0;

    move-result-object v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception v2

    goto :goto_2

    :cond_0
    :goto_0
    if-eqz v1, :cond_1

    :try_start_2
    invoke-virtual {v1}, Landroidx/appcompat/view/menu/gi;->b()V

    goto :goto_1

    :catchall_1
    move-exception v1

    goto :goto_3

    :cond_1
    :goto_1
    monitor-exit v0

    return-object v2

    :goto_2
    if-eqz v1, :cond_2

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/gi;->b()V

    :cond_2
    throw v2

    :goto_3
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    throw v1
.end method

.method public u()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/es;->a:Landroidx/appcompat/view/menu/sr;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/sr;->m()Landroidx/appcompat/view/menu/ss;

    move-result-object v0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ss;->e()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final v(Landroidx/appcompat/view/menu/wh0;)V
    .locals 3

    sget-object v0, Landroidx/appcompat/view/menu/es;->m:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    iget-object v1, p0, Landroidx/appcompat/view/menu/es;->a:Landroidx/appcompat/view/menu/sr;

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/sr;->j()Landroid/content/Context;

    move-result-object v1

    const-string v2, "generatefid.lock"

    invoke-static {v1, v2}, Landroidx/appcompat/view/menu/gi;->a(Landroid/content/Context;Ljava/lang/String;)Landroidx/appcompat/view/menu/gi;

    move-result-object v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :try_start_1
    iget-object v2, p0, Landroidx/appcompat/view/menu/es;->c:Landroidx/appcompat/view/menu/vh0;

    invoke-virtual {v2, p1}, Landroidx/appcompat/view/menu/vh0;->b(Landroidx/appcompat/view/menu/wh0;)Landroidx/appcompat/view/menu/wh0;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    if-eqz v1, :cond_0

    :try_start_2
    invoke-virtual {v1}, Landroidx/appcompat/view/menu/gi;->b()V

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_0
    :goto_0
    monitor-exit v0

    return-void

    :catchall_1
    move-exception p1

    if-eqz v1, :cond_1

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/gi;->b()V

    :cond_1
    throw p1

    :goto_1
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    throw p1
.end method

.method public final synthetic w(Z)V
    .locals 0

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/es;->j(Z)V

    return-void
.end method

.method public final synthetic x()V
    .locals 1

    const/4 v0, 0x0

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/es;->k(Z)V

    return-void
.end method

.method public final synthetic y(Z)V
    .locals 0

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/es;->k(Z)V

    return-void
.end method
