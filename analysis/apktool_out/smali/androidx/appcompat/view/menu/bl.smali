.class public final synthetic Landroidx/appcompat/view/menu/bl;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/util/concurrent/Callable;


# instance fields
.field public final synthetic a:Landroidx/appcompat/view/menu/el;

.field public final synthetic b:Ljava/util/concurrent/Callable;

.field public final synthetic c:Landroidx/appcompat/view/menu/fl$b;


# direct methods
.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/el;Ljava/util/concurrent/Callable;Landroidx/appcompat/view/menu/fl$b;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/bl;->a:Landroidx/appcompat/view/menu/el;

    iput-object p2, p0, Landroidx/appcompat/view/menu/bl;->b:Ljava/util/concurrent/Callable;

    iput-object p3, p0, Landroidx/appcompat/view/menu/bl;->c:Landroidx/appcompat/view/menu/fl$b;

    return-void
.end method


# virtual methods
.method public final call()Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Landroidx/appcompat/view/menu/bl;->a:Landroidx/appcompat/view/menu/el;

    iget-object v1, p0, Landroidx/appcompat/view/menu/bl;->b:Ljava/util/concurrent/Callable;

    iget-object v2, p0, Landroidx/appcompat/view/menu/bl;->c:Landroidx/appcompat/view/menu/fl$b;

    invoke-static {v0, v1, v2}, Landroidx/appcompat/view/menu/el;->d(Landroidx/appcompat/view/menu/el;Ljava/util/concurrent/Callable;Landroidx/appcompat/view/menu/fl$b;)Ljava/util/concurrent/Future;

    move-result-object v0

    return-object v0
.end method
