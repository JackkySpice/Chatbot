.class public final Landroidx/appcompat/view/menu/f41;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/uq;


# instance fields
.field public final a:Landroidx/appcompat/view/menu/zk0;

.field public final b:Landroidx/appcompat/view/menu/zk0;

.field public final c:Landroidx/appcompat/view/menu/zk0;

.field public final d:Landroidx/appcompat/view/menu/zk0;

.field public final e:Landroidx/appcompat/view/menu/zk0;

.field public final f:Landroidx/appcompat/view/menu/zk0;

.field public final g:Landroidx/appcompat/view/menu/zk0;

.field public final h:Landroidx/appcompat/view/menu/zk0;

.field public final i:Landroidx/appcompat/view/menu/zk0;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/f41;->a:Landroidx/appcompat/view/menu/zk0;

    iput-object p2, p0, Landroidx/appcompat/view/menu/f41;->b:Landroidx/appcompat/view/menu/zk0;

    iput-object p3, p0, Landroidx/appcompat/view/menu/f41;->c:Landroidx/appcompat/view/menu/zk0;

    iput-object p4, p0, Landroidx/appcompat/view/menu/f41;->d:Landroidx/appcompat/view/menu/zk0;

    iput-object p5, p0, Landroidx/appcompat/view/menu/f41;->e:Landroidx/appcompat/view/menu/zk0;

    iput-object p6, p0, Landroidx/appcompat/view/menu/f41;->f:Landroidx/appcompat/view/menu/zk0;

    iput-object p7, p0, Landroidx/appcompat/view/menu/f41;->g:Landroidx/appcompat/view/menu/zk0;

    iput-object p8, p0, Landroidx/appcompat/view/menu/f41;->h:Landroidx/appcompat/view/menu/zk0;

    iput-object p9, p0, Landroidx/appcompat/view/menu/f41;->i:Landroidx/appcompat/view/menu/zk0;

    return-void
.end method

.method public static a(Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;)Landroidx/appcompat/view/menu/f41;
    .locals 11

    new-instance v10, Landroidx/appcompat/view/menu/f41;

    move-object v0, v10

    move-object v1, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move-object v5, p4

    move-object/from16 v6, p5

    move-object/from16 v7, p6

    move-object/from16 v8, p7

    move-object/from16 v9, p8

    invoke-direct/range {v0 .. v9}, Landroidx/appcompat/view/menu/f41;-><init>(Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;)V

    return-object v10
.end method

.method public static c(Landroid/content/Context;Landroidx/appcompat/view/menu/q7;Landroidx/appcompat/view/menu/fp;Landroidx/appcompat/view/menu/la1;Ljava/util/concurrent/Executor;Landroidx/appcompat/view/menu/ly0;Landroidx/appcompat/view/menu/dc;Landroidx/appcompat/view/menu/dc;Landroidx/appcompat/view/menu/wb;)Landroidx/appcompat/view/menu/e41;
    .locals 11

    new-instance v10, Landroidx/appcompat/view/menu/e41;

    move-object v0, v10

    move-object v1, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move-object v5, p4

    move-object/from16 v6, p5

    move-object/from16 v7, p6

    move-object/from16 v8, p7

    move-object/from16 v9, p8

    invoke-direct/range {v0 .. v9}, Landroidx/appcompat/view/menu/e41;-><init>(Landroid/content/Context;Landroidx/appcompat/view/menu/q7;Landroidx/appcompat/view/menu/fp;Landroidx/appcompat/view/menu/la1;Ljava/util/concurrent/Executor;Landroidx/appcompat/view/menu/ly0;Landroidx/appcompat/view/menu/dc;Landroidx/appcompat/view/menu/dc;Landroidx/appcompat/view/menu/wb;)V

    return-object v10
.end method


# virtual methods
.method public b()Landroidx/appcompat/view/menu/e41;
    .locals 10

    iget-object v0, p0, Landroidx/appcompat/view/menu/f41;->a:Landroidx/appcompat/view/menu/zk0;

    invoke-interface {v0}, Landroidx/appcompat/view/menu/zk0;->get()Ljava/lang/Object;

    move-result-object v0

    move-object v1, v0

    check-cast v1, Landroid/content/Context;

    iget-object v0, p0, Landroidx/appcompat/view/menu/f41;->b:Landroidx/appcompat/view/menu/zk0;

    invoke-interface {v0}, Landroidx/appcompat/view/menu/zk0;->get()Ljava/lang/Object;

    move-result-object v0

    move-object v2, v0

    check-cast v2, Landroidx/appcompat/view/menu/q7;

    iget-object v0, p0, Landroidx/appcompat/view/menu/f41;->c:Landroidx/appcompat/view/menu/zk0;

    invoke-interface {v0}, Landroidx/appcompat/view/menu/zk0;->get()Ljava/lang/Object;

    move-result-object v0

    move-object v3, v0

    check-cast v3, Landroidx/appcompat/view/menu/fp;

    iget-object v0, p0, Landroidx/appcompat/view/menu/f41;->d:Landroidx/appcompat/view/menu/zk0;

    invoke-interface {v0}, Landroidx/appcompat/view/menu/zk0;->get()Ljava/lang/Object;

    move-result-object v0

    move-object v4, v0

    check-cast v4, Landroidx/appcompat/view/menu/la1;

    iget-object v0, p0, Landroidx/appcompat/view/menu/f41;->e:Landroidx/appcompat/view/menu/zk0;

    invoke-interface {v0}, Landroidx/appcompat/view/menu/zk0;->get()Ljava/lang/Object;

    move-result-object v0

    move-object v5, v0

    check-cast v5, Ljava/util/concurrent/Executor;

    iget-object v0, p0, Landroidx/appcompat/view/menu/f41;->f:Landroidx/appcompat/view/menu/zk0;

    invoke-interface {v0}, Landroidx/appcompat/view/menu/zk0;->get()Ljava/lang/Object;

    move-result-object v0

    move-object v6, v0

    check-cast v6, Landroidx/appcompat/view/menu/ly0;

    iget-object v0, p0, Landroidx/appcompat/view/menu/f41;->g:Landroidx/appcompat/view/menu/zk0;

    invoke-interface {v0}, Landroidx/appcompat/view/menu/zk0;->get()Ljava/lang/Object;

    move-result-object v0

    move-object v7, v0

    check-cast v7, Landroidx/appcompat/view/menu/dc;

    iget-object v0, p0, Landroidx/appcompat/view/menu/f41;->h:Landroidx/appcompat/view/menu/zk0;

    invoke-interface {v0}, Landroidx/appcompat/view/menu/zk0;->get()Ljava/lang/Object;

    move-result-object v0

    move-object v8, v0

    check-cast v8, Landroidx/appcompat/view/menu/dc;

    iget-object v0, p0, Landroidx/appcompat/view/menu/f41;->i:Landroidx/appcompat/view/menu/zk0;

    invoke-interface {v0}, Landroidx/appcompat/view/menu/zk0;->get()Ljava/lang/Object;

    move-result-object v0

    move-object v9, v0

    check-cast v9, Landroidx/appcompat/view/menu/wb;

    invoke-static/range {v1 .. v9}, Landroidx/appcompat/view/menu/f41;->c(Landroid/content/Context;Landroidx/appcompat/view/menu/q7;Landroidx/appcompat/view/menu/fp;Landroidx/appcompat/view/menu/la1;Ljava/util/concurrent/Executor;Landroidx/appcompat/view/menu/ly0;Landroidx/appcompat/view/menu/dc;Landroidx/appcompat/view/menu/dc;Landroidx/appcompat/view/menu/wb;)Landroidx/appcompat/view/menu/e41;

    move-result-object v0

    return-object v0
.end method

.method public bridge synthetic get()Ljava/lang/Object;
    .locals 1

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/f41;->b()Landroidx/appcompat/view/menu/e41;

    move-result-object v0

    return-object v0
.end method
