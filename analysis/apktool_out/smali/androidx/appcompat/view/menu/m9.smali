.class public final Landroidx/appcompat/view/menu/m9;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final a:Ljava/util/concurrent/locks/ReentrantLock;

.field public final b:Ljava/util/Map;


# direct methods
.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/util/concurrent/locks/ReentrantLock;

    invoke-direct {v0}, Ljava/util/concurrent/locks/ReentrantLock;-><init>()V

    iput-object v0, p0, Landroidx/appcompat/view/menu/m9;->a:Ljava/util/concurrent/locks/ReentrantLock;

    new-instance v0, Ljava/util/LinkedHashMap;

    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    iput-object v0, p0, Landroidx/appcompat/view/menu/m9;->b:Ljava/util/Map;

    return-void
.end method


# virtual methods
.method public final a(Ljava/util/concurrent/Executor;Landroidx/appcompat/view/menu/of;Landroidx/appcompat/view/menu/ws;)V
    .locals 7

    const-string v0, "executor"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "consumer"

    invoke-static {p2, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "flow"

    invoke-static {p3, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/m9;->a:Ljava/util/concurrent/locks/ReentrantLock;

    invoke-interface {v0}, Ljava/util/concurrent/locks/Lock;->lock()V

    :try_start_0
    iget-object v1, p0, Landroidx/appcompat/view/menu/m9;->b:Ljava/util/Map;

    invoke-interface {v1, p2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    if-nez v1, :cond_0

    invoke-static {p1}, Landroidx/appcompat/view/menu/wp;->a(Ljava/util/concurrent/Executor;)Landroidx/appcompat/view/menu/mh;

    move-result-object p1

    invoke-static {p1}, Landroidx/appcompat/view/menu/th;->a(Landroidx/appcompat/view/menu/jh;)Landroidx/appcompat/view/menu/sh;

    move-result-object v1

    iget-object p1, p0, Landroidx/appcompat/view/menu/m9;->b:Ljava/util/Map;

    const/4 v2, 0x0

    const/4 v3, 0x0

    new-instance v4, Landroidx/appcompat/view/menu/m9$a;

    const/4 v5, 0x0

    invoke-direct {v4, p3, p2, v5}, Landroidx/appcompat/view/menu/m9$a;-><init>(Landroidx/appcompat/view/menu/ws;Landroidx/appcompat/view/menu/of;Landroidx/appcompat/view/menu/wg;)V

    const/4 v5, 0x3

    const/4 v6, 0x0

    invoke-static/range {v1 .. v6}, Landroidx/appcompat/view/menu/a9;->d(Landroidx/appcompat/view/menu/sh;Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/wh;Landroidx/appcompat/view/menu/xw;ILjava/lang/Object;)Landroidx/appcompat/view/menu/n60;

    move-result-object p3

    invoke-interface {p1, p2, p3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_0
    :goto_0
    sget-object p1, Landroidx/appcompat/view/menu/n31;->a:Landroidx/appcompat/view/menu/n31;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-interface {v0}, Ljava/util/concurrent/locks/Lock;->unlock()V

    return-void

    :goto_1
    invoke-interface {v0}, Ljava/util/concurrent/locks/Lock;->unlock()V

    throw p1
.end method

.method public final b(Landroidx/appcompat/view/menu/of;)V
    .locals 4

    const-string v0, "consumer"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/m9;->a:Ljava/util/concurrent/locks/ReentrantLock;

    invoke-interface {v0}, Ljava/util/concurrent/locks/Lock;->lock()V

    :try_start_0
    iget-object v1, p0, Landroidx/appcompat/view/menu/m9;->b:Ljava/util/Map;

    invoke-interface {v1, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroidx/appcompat/view/menu/n60;

    if-eqz v1, :cond_0

    const/4 v2, 0x1

    const/4 v3, 0x0

    invoke-static {v1, v3, v2, v3}, Landroidx/appcompat/view/menu/n60$a;->a(Landroidx/appcompat/view/menu/n60;Ljava/util/concurrent/CancellationException;ILjava/lang/Object;)V

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_0
    :goto_0
    iget-object v1, p0, Landroidx/appcompat/view/menu/m9;->b:Ljava/util/Map;

    invoke-interface {v1, p1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroidx/appcompat/view/menu/n60;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-interface {v0}, Ljava/util/concurrent/locks/Lock;->unlock()V

    return-void

    :goto_1
    invoke-interface {v0}, Ljava/util/concurrent/locks/Lock;->unlock()V

    throw p1
.end method
