.class public final synthetic Landroidx/appcompat/view/menu/wk;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/fl$c;


# instance fields
.field public final synthetic a:Landroidx/appcompat/view/menu/el;

.field public final synthetic b:Ljava/lang/Runnable;

.field public final synthetic c:J

.field public final synthetic d:J

.field public final synthetic e:Ljava/util/concurrent/TimeUnit;


# direct methods
.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/el;Ljava/lang/Runnable;JJLjava/util/concurrent/TimeUnit;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/wk;->a:Landroidx/appcompat/view/menu/el;

    iput-object p2, p0, Landroidx/appcompat/view/menu/wk;->b:Ljava/lang/Runnable;

    iput-wide p3, p0, Landroidx/appcompat/view/menu/wk;->c:J

    iput-wide p5, p0, Landroidx/appcompat/view/menu/wk;->d:J

    iput-object p7, p0, Landroidx/appcompat/view/menu/wk;->e:Ljava/util/concurrent/TimeUnit;

    return-void
.end method


# virtual methods
.method public final a(Landroidx/appcompat/view/menu/fl$b;)Ljava/util/concurrent/ScheduledFuture;
    .locals 8

    iget-object v0, p0, Landroidx/appcompat/view/menu/wk;->a:Landroidx/appcompat/view/menu/el;

    iget-object v1, p0, Landroidx/appcompat/view/menu/wk;->b:Ljava/lang/Runnable;

    iget-wide v2, p0, Landroidx/appcompat/view/menu/wk;->c:J

    iget-wide v4, p0, Landroidx/appcompat/view/menu/wk;->d:J

    iget-object v6, p0, Landroidx/appcompat/view/menu/wk;->e:Ljava/util/concurrent/TimeUnit;

    move-object v7, p1

    invoke-static/range {v0 .. v7}, Landroidx/appcompat/view/menu/el;->i(Landroidx/appcompat/view/menu/el;Ljava/lang/Runnable;JJLjava/util/concurrent/TimeUnit;Landroidx/appcompat/view/menu/fl$b;)Ljava/util/concurrent/ScheduledFuture;

    move-result-object p1

    return-object p1
.end method
