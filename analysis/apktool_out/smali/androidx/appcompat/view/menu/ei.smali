.class public final Landroidx/appcompat/view/menu/ei;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/uq;


# instance fields
.field public final a:Landroidx/appcompat/view/menu/zk0;

.field public final b:Landroidx/appcompat/view/menu/zk0;

.field public final c:Landroidx/appcompat/view/menu/zk0;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/ei;->a:Landroidx/appcompat/view/menu/zk0;

    iput-object p2, p0, Landroidx/appcompat/view/menu/ei;->b:Landroidx/appcompat/view/menu/zk0;

    iput-object p3, p0, Landroidx/appcompat/view/menu/ei;->c:Landroidx/appcompat/view/menu/zk0;

    return-void
.end method

.method public static a(Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;)Landroidx/appcompat/view/menu/ei;
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/ei;

    invoke-direct {v0, p0, p1, p2}, Landroidx/appcompat/view/menu/ei;-><init>(Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;)V

    return-object v0
.end method

.method public static c(Landroid/content/Context;Landroidx/appcompat/view/menu/dc;Landroidx/appcompat/view/menu/dc;)Landroidx/appcompat/view/menu/di;
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/di;

    invoke-direct {v0, p0, p1, p2}, Landroidx/appcompat/view/menu/di;-><init>(Landroid/content/Context;Landroidx/appcompat/view/menu/dc;Landroidx/appcompat/view/menu/dc;)V

    return-object v0
.end method


# virtual methods
.method public b()Landroidx/appcompat/view/menu/di;
    .locals 3

    iget-object v0, p0, Landroidx/appcompat/view/menu/ei;->a:Landroidx/appcompat/view/menu/zk0;

    invoke-interface {v0}, Landroidx/appcompat/view/menu/zk0;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/content/Context;

    iget-object v1, p0, Landroidx/appcompat/view/menu/ei;->b:Landroidx/appcompat/view/menu/zk0;

    invoke-interface {v1}, Landroidx/appcompat/view/menu/zk0;->get()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroidx/appcompat/view/menu/dc;

    iget-object v2, p0, Landroidx/appcompat/view/menu/ei;->c:Landroidx/appcompat/view/menu/zk0;

    invoke-interface {v2}, Landroidx/appcompat/view/menu/zk0;->get()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Landroidx/appcompat/view/menu/dc;

    invoke-static {v0, v1, v2}, Landroidx/appcompat/view/menu/ei;->c(Landroid/content/Context;Landroidx/appcompat/view/menu/dc;Landroidx/appcompat/view/menu/dc;)Landroidx/appcompat/view/menu/di;

    move-result-object v0

    return-object v0
.end method

.method public bridge synthetic get()Ljava/lang/Object;
    .locals 1

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/ei;->b()Landroidx/appcompat/view/menu/di;

    move-result-object v0

    return-object v0
.end method
