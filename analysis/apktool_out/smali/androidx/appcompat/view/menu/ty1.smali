.class public final Landroidx/appcompat/view/menu/ty1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic m:Landroidx/appcompat/view/menu/vy0;

.field public final synthetic n:Landroidx/appcompat/view/menu/w02;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/w02;Landroidx/appcompat/view/menu/vy0;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/ty1;->n:Landroidx/appcompat/view/menu/w02;

    iput-object p2, p0, Landroidx/appcompat/view/menu/ty1;->m:Landroidx/appcompat/view/menu/vy0;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 3

    iget-object v0, p0, Landroidx/appcompat/view/menu/ty1;->n:Landroidx/appcompat/view/menu/w02;

    invoke-static {v0}, Landroidx/appcompat/view/menu/w02;->c(Landroidx/appcompat/view/menu/w02;)Ljava/lang/Object;

    move-result-object v0

    monitor-enter v0

    :try_start_0
    iget-object v1, p0, Landroidx/appcompat/view/menu/ty1;->n:Landroidx/appcompat/view/menu/w02;

    invoke-static {v1}, Landroidx/appcompat/view/menu/w02;->a(Landroidx/appcompat/view/menu/w02;)Landroidx/appcompat/view/menu/cg0;

    move-result-object v2

    if-eqz v2, :cond_0

    invoke-static {v1}, Landroidx/appcompat/view/menu/w02;->a(Landroidx/appcompat/view/menu/w02;)Landroidx/appcompat/view/menu/cg0;

    move-result-object v1

    iget-object v2, p0, Landroidx/appcompat/view/menu/ty1;->m:Landroidx/appcompat/view/menu/vy0;

    invoke-interface {v1, v2}, Landroidx/appcompat/view/menu/cg0;->a(Landroidx/appcompat/view/menu/vy0;)V

    goto :goto_0

    :catchall_0
    move-exception v1

    goto :goto_1

    :cond_0
    :goto_0
    monitor-exit v0

    return-void

    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw v1
.end method
