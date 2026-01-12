.class public final synthetic Landroidx/appcompat/view/menu/sk;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/fl$c;


# instance fields
.field public final synthetic a:Landroidx/appcompat/view/menu/el;

.field public final synthetic b:Ljava/util/concurrent/Callable;

.field public final synthetic c:J

.field public final synthetic d:Ljava/util/concurrent/TimeUnit;


# direct methods
.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/el;Ljava/util/concurrent/Callable;JLjava/util/concurrent/TimeUnit;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/sk;->a:Landroidx/appcompat/view/menu/el;

    iput-object p2, p0, Landroidx/appcompat/view/menu/sk;->b:Ljava/util/concurrent/Callable;

    iput-wide p3, p0, Landroidx/appcompat/view/menu/sk;->c:J

    iput-object p5, p0, Landroidx/appcompat/view/menu/sk;->d:Ljava/util/concurrent/TimeUnit;

    return-void
.end method


# virtual methods
.method public final a(Landroidx/appcompat/view/menu/fl$b;)Ljava/util/concurrent/ScheduledFuture;
    .locals 6

    iget-object v0, p0, Landroidx/appcompat/view/menu/sk;->a:Landroidx/appcompat/view/menu/el;

    iget-object v1, p0, Landroidx/appcompat/view/menu/sk;->b:Ljava/util/concurrent/Callable;

    iget-wide v2, p0, Landroidx/appcompat/view/menu/sk;->c:J

    iget-object v4, p0, Landroidx/appcompat/view/menu/sk;->d:Ljava/util/concurrent/TimeUnit;

    move-object v5, p1

    invoke-static/range {v0 .. v5}, Landroidx/appcompat/view/menu/el;->g(Landroidx/appcompat/view/menu/el;Ljava/util/concurrent/Callable;JLjava/util/concurrent/TimeUnit;Landroidx/appcompat/view/menu/fl$b;)Ljava/util/concurrent/ScheduledFuture;

    move-result-object p1

    return-object p1
.end method
